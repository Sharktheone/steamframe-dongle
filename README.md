# I reverse engineered the Steam Frame's wireless adapter

Are you like me and thought that the Adapter was the Router? Well, no. The adapter is just a WiFi 6E dongle that connects to the headset's own hidden hotspot.

> Just here for the tool? Jump to [Want To Try It?](#want-to-try-it). Here for the story? Keep reading.

## Why?

But let's start from the beginning. I wanted to play Half-Life: Alyx on the Frame but forgot the Adapter at someone else's house. I didn't want that to stop me from playing.
The issue is that my home WiFi is just an old GL.iNet travel router which only supports 2.4GHz. With just that it is pretty much impossible to have a good time playing.

## The Hotspot Solution

So the first thing I did was to just use the WiFi 6E card on my PC's motherboard. It seemed to work way better but latency spikes still were killing the experience.

The Frame can stream over two WiFi links at the same time (Valve calls this Multilink). As far as I can tell, that's the trick against latency spikes: when one link hiccups, the other one hopefully doesn't hiccup at the exact same moment. With only one link, every single spike ends up right on your face.

So the Frame can do two links, but my PC only has one WiFi card. And I don't own another WiFi 6E card... or so I thought. Turns out laptops have WiFi too. So I grabbed my MacBook and used it as a hotspot while it was connected to my network over Ethernet. In typical Apple fashion this was not as straightforward and very buggy to set up. However once it worked, I had a new AP which I could even move and that was not stuck to an antenna somewhere under my desk.

## The "Adapter"

As you might have guessed by now, the MacBook hotspot situation again has only one radio and I had no adapter. So I needed to use the same mechanism as the Adapter to connect my PC's WiFi card to the Frame somehow. At that time I did indeed not know that it is just a hidden hotspot from the Frame side. I searched every settings menu to see if I can change where the second radio connects to, but found nothing.

Luckily the Frame is just Linux. Linux machines normally have terminals. Terminals normally don't hide their secrets. Secrets normally are just a command away.
To make my job even easier, Valve actually gives an option to enable SSH on the Frame.
Once I connected to the Frame via SSH, I found out that `softapmanager` is used and it opened a hidden network called `frame_XXXXXXXX` plus a 32 character password. It uses the separate `wlanap` interface.

On my PC I just connected to that network and it worked... ish?

## Multilink Streaming

Streaming via Multilink (so over both radios) worked! But is my motherboard WiFi card now an official Valve adapter? Depends on who you ask.

The Frame has two different places that show the adapter. The first one says Valve's adapter is not connected. Fair enough, it isn't. But once you actually connect and look at the other one, it proudly tells you that you're connected via WiFi and Valve's own adapter!

So the Frame disagrees with itself. And SteamVR? SteamVR said the adapter was connected the whole time. If even the Frame is confused, I don't feel too bad about being confused either.

## A Small SteamVR Rant (Feel Free To Skip)

Quick detour before the interesting part. SteamVR on Linux is... an experience.

Connecting, even without my Frankenstein setup, was a pain. Sometimes it took a minute to connect. And every time I pressed the connect button while waiting? Saved up and replayed afterwards. All of them. Great experience!

I've also seen a number of interesting crashes in both SteamVR and Half-Life: Alyx. No idea if that's the Frame or just Linux being Linux. One of them I traced down to a poisoned mutex in Alyx, which then spawned an SDL window, blocking, on the main thread. So the game looked frozen or crashed while it was really just waiting on that window.

Okay, rant over. Back to the WiFi.

## Okay, this is nice, but how does it work?

So far I knew three things: the Frame has a hidden hotspot, it runs on its own `wlanap` interface, and the Adapter is just a WiFi 6E dongle. What I didn't know: how does Steam know the credentials for that hotspot?

My goal was simple: A tool which connects your PC to the Frame's hidden hotspot, without the Adapter and without SSH. And oh, I am unsure if I would do it again...

Getting the credentials was easy if the Adapter had been connected once, since Steam stores them in a NetworkManager profile. But I wanted them without ever having connected the Adapter.

This is the part where my understanding of how it works changed multiple times!

## Down The steamclient.so Rabbit Hole

So I found a really cursed way to get them. The credentials usually get shared via Steam's local Remote Play protocol, and the thing speaking that protocol on your PC is `steamclient.so`. So the plan was: load `steamclient.so` into my own program, connect to the running Steam and just ask it nicely.

Here is how "just ask it nicely" went:

1. Load `steamclient.so`, call `CreateInterface`, connect to the running Steam over its IPC pipe. So far so good!
2. Find the methods I need, like `PairViaWifiAP`. They exist! They're just not exported. They live in private C++ interfaces nobody is supposed to touch.
3. No exports, so I go through the vtable. Object pointer, table of function pointers, pick the right slot, call it and hope.
4. To find the right functions, read the ELF at runtime and look for the instructions that load the method's name. Then hash every function I call, so I don't accidentally call something else.
5. Steam updates. 15 of 16 hashes change. `PairViaWifiAP` moves from slot 55 to slot 61.
6. Add an option to ignore the hashes. Basically a "trust me bro" flag.
7. Steam beta: "Steam has no `GetRemoteClientCount`". It does! The compiler just loaded the string into `R13` first and then moved it to `RCX`, and my scanner only looked for `RCX`.
8. Write an actual instruction decoder that follows registers around. In theory it now recognizes every Steam version I could find, going back a year. In theory....

It was a real mess and some of the worst code I have ever written, but it worked. I was able to get the credentials from Steam directly without having the adapter connected!

## Works On My Machine

Well, the only problem was that the other machine was also mine.

On my second PC, which never had the Adapter connected, it just didn't work. So I spent a lot of time debugging different `steamclient.so` versions, only to realize that my mental model was fully wrong.

My mental model: the Frame owns the password, and Steam asks for it. So I just had to find the asking part.

Reality: Steam on my second PC never got the credentials. It never even tried. And my main PC? It just handed me cached credentials from the last time the real Adapter was paired. So my "it works!" was actually "it remembers!".

## The Clue

Looking back, two error messages should have tipped me off way earlier.

The first time I talked the Remote Play protocol myself, I got: "unauthorized". Fair. Just being on the same LAN doesn't mean you get to mess with someone's hotspot. You need to be paired.

Much later I came back with proper authentication and asked again. This time it didn't say "unauthorized". It said: "No dongle present."

Not "here is your password". Not "go away". "No dongle present." As if the dongle had to bring something to the table... Oh fuck wait!?

## Reverse Flow For Credentials

Turns out that neither the Frame nor the adapter is responsible for setting up the credentials. It is Steam itself. Steam derives an SSID and password using information from the adapter and sends them to the Frame via the Remote Play protocol. The Frame then sets up its hotspot with those credentials.

So all I had to do was the same thing Steam does, just without the adapter. By default the tool generates a random SSID and password, but you can also pick your own and use your creativity!

Interestingly enough, this works the exact opposite way of how the Frame WiFi works itself. The Frame opens the AP and the adapter connects to it. Normally the access point picks the credentials and the clients join. Here, the PC decides, and the Frame, the actual AP, just hosts whatever it's told.

## How It Works Now

All that cursed `steamclient.so` code? Gone. Deleted. Never to be seen again, I hated it anyways.

Instead, it just speaks the Remote Play LAN protocol itself:

1. Find the Frame on your normal LAN, the same way Steam does.
2. Connect using the keys Steam already saved when you paired your PC with the Frame. So yes, you still need to pair them in Steam once.
3. Tell the Frame "yes, I totally have a dongle". There is literally a `wifi_dongle_present` flag for that.
4. Hand it an SSID and password.
5. Wait for the Frame to confirm it actually took them.

After that, NetworkManager connects your WiFi card to the Frame's new hotspot. No dongle, no SSH, no reading assembly at runtime.

## Want To Try It?

You need:

- Linux with NetworkManager
- A WiFi card that can do 6GHz and WPA3, and a regulatory domain that allows it. The Frame's hotspot used 6GHz, 160MHz and WPA3-SAE in my setup, so an old 2.4GHz card won't cut it.
- Steam running with Remote Play enabled, as the same user that runs the tool
- Your PC already paired with the Frame in Steam
- The Frame awake and on the same LAN as your PC
- Rust, OpenSSL 3 development libraries and `pkg-config` to build it (or just download it from actions)

```sh
cargo build --release
./target/release/steamframe-link devices

# Generate credentials, send them to the Frame, and save them locally.
./target/release/steamframe-link set-creds

# Connect your WiFi card using the saved credentials.
./target/release/steamframe-link setup --iface wlan0
```

Want to pick your own SSID and password? Get creative:

```sh
./target/release/steamframe-link set-creds --ssid frame_MYPC --psk-stdin
```

> **Heads up:** `set-creds` changes the Frame's hotspot and can interrupt its current wireless connection.

The profile on your PC doesn't become your default route, so your normal internet keeps working while you're connected to the Frame.

<details>
<summary>All the other options</summary>

- **Passwords** must be 8 to 63 printable ASCII characters, SSIDs 1 to 32 bytes without control characters. `--psk PASSWORD` works too, but puts the password in your shell history.
- **Saved credentials** live in `$XDG_STATE_HOME/steamframe-link/CLIENT_ID.json` (default `~/.local/state/steamframe-link/`). They're saved *before* sending, so a dropped connection can't lose a generated password. Retry them with `set-creds --saved`, show them with `set-creds --saved --reveal`.
- **Confirmation:** the tool only treats credentials as set when the Frame answers with success or reports the matching network hash. A disconnect or timeout is never success, and `setup` refuses unconfirmed credentials.
- **Several Frames:** use the ID from `devices` with `--client ID`. (If you really have multiply, why not send one to me? 🫣)
- **Discovery blocked?** Use `--host FRAME_LAN_IPV4`. `--steam-dir PATH` picks another Steam install, `--timeout SECONDS` sets the provisioning deadline (default 30s).
- **All in one:** `setup --provision --iface wlan0` provisions the Frame and sets up your PC.
- **Already know the credentials?** `setup --iface wlan0 --ssid NAME --psk-stdin` doesn't touch the Frame. `setup --from-nm` copies Steam's existing NetworkManager profile.
- Plain `setup` doesn't need Steam running or LAN discovery.
- `--no-connect` saves the PC profile without activating it, `--no-autoconnect` disables autoconnect.
- Without `--iface`, the tool auto-detects Valve's adapter. The profile uses WPA3-SAE with required management frame protection, hidden SSID probing, no power saving and the radio's permanent MAC. `--wpa2` is there for compatible setups.
- Manage the PC profile with `up --iface wlan0`, `down --iface wlan0` and `remove`.

</details>

## So, Was It Worth It?

Was it faster than just picking up the Adapter from where I left it? No. Not even close.

But I now know more about the Steam Frame, the Remote Play protocol and `steamclient.so` than I ever wanted to. And you can now (hopefully) use your own 6GHz or 7GHz  (⁶🤷⁷) WiFi card as your "Adapter". 

If you made it this far, consider smashing that ⭐ at the top of this page. It costs you nothing and makes me very happy. And when a Steam update inevitably breaks something, you know where the issues tab is.

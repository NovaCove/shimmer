shimmer
-----

**WARNING: THIS IS NOT STABLE - USE AT YOUR OWN RISK**

The goal of this project is to provide a simple, transparent way to encrypt filesystems in a manner that allows authenticated processes to access them as if they were plaintext.

Why? Because so many tools rely on known file locations for plaintext files, `~/.npmrc`, `~/.aws/credentials`, and on and on.

The goal with `shimmer`, is to allow authenticated process trees to access these files as normal, while they don't seem to exist to non-authenticated processes... perhaps `mirage` would have been a better name.

# Milestones
 1. [ ] Functional prototype that supports TTLs per mount, but does not enforce per-process authentication
 2. [ ] Support per-process authentication
 3. [ ] Support retrieval and syncing of remote encrypted filesystems


## Proof it works
Follow these instructions:

In one terminal session:
```sh
git clone git@github.com:NovaCove/shimmer.git
cd shimmer
make dev
./shimmer server
```

In a second terminal session:
```sh
# Add the directory to shimmer, note that this will delete it from where it originally was.
./shimmer fs register --name=example-demo --src=./example/demo --remove-on-import=true

# Check that it's gone, oh my!
ls ./example/demo

# Mount the directory to a new place to show that we can.
./shimmer fs mount --name example-demo --mount ./example/demo-new 

# Checking the new directory out.
tree ./example/demo-new

# Unmount the directory
./shimmer fs unmount --name example-demo --mount ./example/demo-new

# Eject the encrypted filesystem back to whence it came.
./shimmer fs eject --name example-demo

# Proving that it's back to how it was.
tree ./example/demo
```



*** ALL BELOW IS WISHFUL THINKING ***

# Getting Started

## Installation
```
# Homebrew formula not yet registered
brew install shimmer
```

## Initial boostrap
```
shimmer bootstrap
```



# Internals
## Architecture
 - There is a daemon that runs, and can be installed to run via launchctl
 - The core shimmerd server (the daemon above), responds to client interactons via RPC over a unix socket.
 - It launches local NFS servers to locally mount drives to emulate file system access.
 - When shutting down, it cleans up each of these NFS servers, to remove any dangling mounts.


## Config
(honestly this isn't really used yet, but is idealistic)

The config should contain information such as:

 - directory structures and links to file content, and whether it is read-only or read/write
 - a way to source initial information
 - get notifications of failed read attempts
 - drop honeypots (which ones to drop)?


## Authentication
 - Ideal authentication flow is that the client uses touchID to get a keychain item that
 is a shared secret value. It then creates a salt and hashes that secret value, to be verified
 by the server.
 - This should be done to authenticate the root process.

 - there's something here to work through around trust, or certain commands running that shuts down
 access to files. perhaps you share a list of process names that are allowed to access a file

 - would node malware change process names? maybe? how could we defend against that?


# Next steps
 - [x] add a locked / unlocked state
 - [x] add TTLs for shutting down mount servers
 - [x] add bootstrap command for initial setup
    - [x] on first run, see if we have a root key, if not, set one up
 - [x] diagnostics command
 - [ ] implement storage for encrypted blobs
 - [ ] implement sqlite db or something similar for access history
   - should be able to use methods wrapping `ContextualFS` to implement access logging
 - [x] share key management in keychain, with rotation based on some value
 - [ ] data config management - loading, showing, editing
 - [ ] initial file import, with safeguards
   - should be something like `shimmer fs register <name> <location> --remove-on-import=false`
 - [ ] better onboarding UX - e.g. some nice colored "shimmer bootstrap" command
 - [ ] Actually harden the rpc protocol - magic cookies, multiplexing, connection lifecycle, etc
 - [ ] log truncation

 ## Future improvements
  - Only use one NFS server, so that we don't need one per mount
  - Fork the go-nfs server to pass user and process information to the server, currently this information is lost.

# Understanding shimmer

## Filesystem mounts

First, a filesystem mount must be registered with the shimmer daemon. This will cause it to ingest and encrypt the entire directory structure. This FS can then be mounted at any other point. Usage would look like:

```sh
# Ingest the directory for testing purpsoes
shimmer fs register gcloud-dotfiles ~/.gcloud --remove-on-import=false

# Now we can mount it - we'll name it "gcloud"
shimmer fs mount gcloud --fs=gcloud-dotfiles --mountpoint=~/.gcloud2 --ttl=8h

# If you log in the next day, you'll need to re-activate it.
shimmer fs activate gcloud
```

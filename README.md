shimmer
-----

The goal of this project is to provide a solution to directory based file accesses (one day we'll come for you, too, single files).

Currently, there is a server and client component. Longer term, we'll have the server load from boot, get it's authentication keys from the keychain, and then be off the the races.

Today, we have a skeleton.

# Getting Started

## Installation
```
brew install shimmer
```

## Initial boostrap



# Internals
## Architecture
 - There is a daemon that runs, and can be installed to run via launchctl
 - The core shimmerd server (the daemon above), responds to client interactons via RPC over a unix socket.
 - It launches local NFS servers to locally mount drives to emulate file system access.
 - When shutting down, it cleans up each of these NFS servers, to remove any dangling mounts.


## Config
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

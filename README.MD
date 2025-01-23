# MMX Key Generator

This tool will generate a mnemonic and derive a Farmer Public Key and a number of addresses (choice of 1, 5, 10, and 20 by default). You also have the choice of supplying a passphrase which is compatible with the MMX client, and additional entropy when generating the mnemonic seed.
This tool is standalone and does not require any preparation or installation to use.

## Usage
The key generator is simple to use, either downloading the precompiled binaries or compile your own binary from source. To create a cold wallet, put the binary on a USB flash drive and bring it to a non-connected computer. Run the binary to generate a mnemonic and derive applicable public keys. Follow the prompts in the command line to generate a key. To copy from the command line in command prompt on windows, use `Ctrl+Shift+c`.

If you choose to use a passphrase, ensure you do not forget it or else you will not be able to access the wallet when importing your mnemonic seed into the MMX client. The passphrase is not stored anywhere, so it is important to remember it.

The mnemonic/private key are not stored anywhere on the system, but you will be given an option to export the public keys/addresses to a text file in the present working directory. You can write down the mnemonic on a piece of paper, then move the public key text file back to the USB for ease of use on your main computer.

### Building From Source
To build the binary from source, you will need to install rust. Follow the instructions here: https://www.rust-lang.org/tools/install

Once rust is installed, clone this repository with `git clone https://github.com/scrutinously/mmx-keygen.git` and then `cd mmx-keygen`.

Using `cargo build --release` will compile the release version of the binary to `key-generator/target/release`. If you intend to use it on a system architecture or operating system other than what you're building it on, you will need to cross compile, so use `cargo install cross` to get rust's cross compiler, and install docker if it's not already installed. To build a release for the Raspberry Pi 4 from a desktop PC for example, you would then need to run `cross build --target aarch64-unknown-linux-musl --release`.
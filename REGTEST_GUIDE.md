✍️ RECOMMENDED REGTEST_GUIDE.md Content

# Fractal Bitcoin Regtest Setup (macOS Guide)

This guide walks you through building and running Fractal Bitcoin in `regtest` mode on macOS.

---

## ✅ Prerequisites

- macOS 13 or newer
- Homebrew installed
- GitHub account
- Xcode Command Line Tools

```bash
xcode-select --install

____________________________________________

📦 Install Dependencies

bash

brew install autoconf automake libtool berkeley-db@4 pkg-config boost

___________________________________________

🧱 Build Fractal

Bash

git clone https://github.com/YOUR_USERNAME/fractal.git
cd fractal
./autogen.sh
./configure --with-incompatible-bdb
make -j$(sysctl -n hw.ncpu)

You should now have fractald and fractal-cli built under ./src.

__________________________________________

⚙️ Set Up Regtest Data Directory

bash

mkdir -p ~/fractal-data
nano ~/fractal-data/bitcoin.conf

Paste into bitcoin.conf:

ini

regtest=1
server=1
daemon=1
rpcuser=fractaluser
rpcpassword=fractalpass

_________________________________________

🚀 Start Fractal Node

bash

./src/fractald -regtest -datadir=$HOME/fractal-data -daemon

_________________________________________

🔧 Use CLI

bash

./src/fractal-cli -regtest -datadir=$HOME/fractal-data getblockchaininfo

_________________________________________

🛑 Stop Node

bash

./src/fractal-cli -regtest -datadir=$HOME/fractal-data stop

__________________________________________

✅ Optional: Mine Test BTC

bash

ADDR=$(./src/fractal-cli -regtest getnewaddress)
./src/fractal-cli -regtest generatetoaddress 101 $ADDR
./src/fractal-cli -regtest getbalance

___________________________________________

🛠️ Bonus: Run All as a Script

Create regtest-quickstart.sh to automate setup.

___________________________________________


🙌 Credits

Contributor: @Phantagyro




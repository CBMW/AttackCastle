# Debian Packaging And APT Repo Beta Flow

This project now includes Debian packaging metadata and helper scripts to support:

- building `attackcastle` `.deb` artifacts
- publishing a repository index so operators can run `apt install attackcastle`
- installing a desktop launcher while keeping `attackcastle gui` as the terminal entry point

## 1) Build The Debian Package

Run on Debian/Kali/Ubuntu:

```bash
sudo apt update
sudo apt install -y dpkg-dev debhelper dh-python pybuild-plugin-pyproject python3-hatchling python3-pytest apt-utils
./scripts/build-deb.sh
```

The generated package appears in the parent directory, for example:

```text
../attackcastle_0.1.0-1_all.deb
```

For a quick local install on a Kali box before you stand up a repo:

```bash
sudo apt install ./../attackcastle_0.1.0-1_all.deb
attackcastle --help
attackcastle gui
```

## 2) Build Repository Metadata

Use `scripts/build-apt-repo.sh` to build `Packages`, `Release`, and optional signatures:

```bash
./scripts/build-apt-repo.sh \
  --repo-root /var/www/html/apt \
  --deb ../attackcastle_0.1.0-1_all.deb \
  --dist stable \
  --component main \
  --arch all \
  --gpg-key "<YOUR-KEY-ID>"
```

If `--gpg-key` is omitted, metadata is unsigned (not recommended for production).

## 3) Client-Side Install

On target Kali VM:

```bash
curl -fsSL <YOUR-REPO-URL>/repo-signing-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/attackcastle-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/attackcastle-archive.gpg] <YOUR-REPO-URL> stable main" | sudo tee /etc/apt/sources.list.d/attackcastle.list
sudo apt update
sudo apt install attackcastle
```

At this point users can launch the GUI from a terminal with:

```bash
attackcastle gui
```

and desktop environments should also show an `AttackCastle` launcher.

## 4) Dependency Bootstrap After Install

Install recommended scanner dependencies in one step:

```bash
attackcastle plugins install-missing --yes
```

Or include it in your preflight:

```bash
attackcastle doctor --install-missing --yes
```

During interactive scans, AttackCastle now prompts to install missing scanner tools via `apt-get`.

## 5) Getting To `apt install attackcastle` Without A Custom Repo

There are two realistic paths:

- Publish and maintain your own APT repository, then document the one-time repository setup step.
- Submit the package through Kali's public packaging flow so it can eventually land in Kali's package repositories.

Until one of those happens, users can still install the generated `.deb` directly with `sudo apt install ./path/to/attackcastle_*.deb`.

## 6) Beta Validation Checklist

Run these in a clean Kali VM snapshot:

```bash
attackcastle --help
attackcastle doctor --output-format json
attackcastle plugins doctor
python3 -c "from attackcastle.gui.window import run"
attackcastle plugins install-missing --yes
attackcastle scan --target example.com --output-dir ./output --profile cautious --dry-run
```

Then manually confirm that `attackcastle gui` opens the desktop application window.

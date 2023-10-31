# make_fself in rust

make_fself in rust because I didn't want to rely on python as a dependency

# Usage

```
Usage: make_fself <INPUT_FILE> <OUTPUT_FILE> [PAID] [PROGRAM_TYPE] [APP_VERSION] [FW_VERSION] [AUTH_INFO]

Arguments:
  <INPUT_FILE>
  <OUTPUT_FILE>
  [PAID]
  [PROGRAM_TYPE]
  [APP_VERSION]
  [FW_VERSION]
  [AUTH_INFO]

Options:
  -h, --help  Print help
```

### Example usage
```bash
$ ./make_fself name.prx name.sprx
```


### Example usage in Visual Studio Project on Post-Build Event
```
cd "$(SolutionDir)vendor\make_fself\bin\"
make_fself.exe "$(TargetDir)$(TargetName)$(TargetExt)" "$(TargetDir)$(TargetName).sprx"
```

# Download
[Releases](https://github.com/TheRouletteBoi/make_fself_rust/releases)


# Building

```bash
$ cargo build --release
```


# Contributors
- flatz for the original make_fself.py script
- unisquirrel for rust help
- Illia rust dev



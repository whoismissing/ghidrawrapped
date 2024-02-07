## GhidraWrapped Plugin

This Ghidra extension will record all undoable actions on save and generate a personalized review of reverse engineering work.

## Building from source

```bash
$ GHIDRA_INSTALL_DIR=/path/to/ghidra gradle buildExtension
```

The extension will be available as a zip file in the `dist/` directory.

```bash
$ ls dist/
-a----          2/6/2024   7:51 PM        5592415 ghidra_10.1.5_PUBLIC_20240206_ghidrawrapped.zip
```

## Installing a release

From Ghidra, go to `File > Install Extensions` and select the corresponding `zip` file.

## Usage

First, set the outgoing file path to record all actions to. This configuration is available under `Edit > Tool Options > ghidrawrapped > Event Filepath`. This should be an absolute filepath.

Go about performing actions in the Ghidra UI such as adding comments, labels, and retyping data structures.

Clicking the save project button in the Ghidra UI will record these actions to the configured event filepath.

Finally, selecting the following sequence `Window > ghidrawrappedPlugin > +` will load the recorded event file and count the various recorded actions and present the overall stats and reverse engineering "personality" type.

## Personalities

## Architect

Reverse engineering actions are mostly related to structures.

![architect](https://raw.githubusercontent.com/whoismissing/ghidrawrapped/master/src/main/resources/images/Architect.png)

## Artist

Reverse engineering actions are mostly graphical.

![artist](https://raw.githubusercontent.com/whoismissing/ghidrawrapped/master/src/main/resources/images/Artist.png)

## Author

Reverse engineering actions are mostly renames.

![author](https://raw.githubusercontent.com/whoismissing/ghidrawrapped/master/src/main/resources/images/Author.png)

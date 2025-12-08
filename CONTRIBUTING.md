# Contributing

## Development Guidelines

#### It's recommended to create a *virtual environment*

```bash
python3 -m venv path/to/venv # e.g. `python3 -m venv .venv`
. path/to/venv/bin/activate  # e.g. `. .venv/bin/activate`
```
> [!NOTE]
> Typically, *'path/to/venv'* is *'.venv'* in the current directory.

> [!TIP]
> Run `deactivate` to deactivate the *virtual environment*.

Please see the [official documentation](https://packaging.python.org/en/latest/tutorials/installing-packages/#optionally-create-a-virtual-environment) for more information.

### Code Style Guidelines

- Ensure your code is well-commented and self-documenting.
- The project enforces code formatting through its [pre-commits](.pre-commit-config.yaml) configuration. Do **NOT** turn off this feature and make sure your `pre-commit run` command works successfully (see [below](#pre-commit) for more details).

#### `pre-commit`

This project uses [pre-commit](https://pre-commit.com/), a framework for managing and maintaining git hooks. Pre-commit can be used to manage the hooks that run on every commit to automatically point out issues in code such as missing semicolons, trailing whitespace, and debug statements. By using these hooks, you can ensure code quality and prevent bad code from being uploaded.

To install `pre-commit`, you can use `pip`:

```bash
pip3 install pre-commit
```

After installation, you can set up your git hooks with this command at the root of this repository:

```bash
pre-commit install
```

This will add a pre-commit script to your `.git/hooks/` directory. This script will run whenever you run `git commit`.

For more details on how to configure and use pre-commit, please refer to the official documentation.

### Commit Message Guidelines

- Write clear, concise commit messages that follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) standard.
- The allowed [types](https://github.com/angular/angular/blob/22b96b9/CONTRIBUTING.md#type) for this project are the following:

    ```yaml
    [
      "build",
      "chore",
      "ci",
      "debug",
      "docs",
      "feat",
      "fix",
      "perf",
      "refactor",
      "remove",
      "style",
      "test"
    ]
    ```

## License and Attribution

This project is licensed under the [MIT License](./LICENSE). By contributing, you agree that your contributions will be licensed under the same terms.

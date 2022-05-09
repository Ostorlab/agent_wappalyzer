<h1 align="center">Agent wappalyzer</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_wappalyzer">
<img src="https://img.shields.io/github/stars/ostorlab/agent_wappalyzer">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_wappalyzer is a web technology fingerprinter capable of detecting CMS, blogging platform, analytics pacakges, JS libraries, web servier and embeded devices._

---

<p align="center">
<img src="https://github.com/Ostorlab/agent_wappalyzer/blob/main/images/logo.png" alt="agent-wappalyzer" />
</p>

This repository is an implementation of [Ostorlab Agent](https://pypi.org/project/ostorlab/) for the [wappalyzer Fingerprinter](https://github.com/urbanadventurer/wappalyzer.git).

## Getting Started
To perform your first scan, simply run the following command.
```shell
ostorlab scan run --install --agent agent/ostorlab/wappalyzer domain-name tesla.com
```

This command will download and install `agent/ostorlab/wappalyzer`.
For more information, please refer to the [Ostorlab Documentation](https://github.com/Ostorlab/ostorlab/blob/main/README.md)


## Usage

Agent wappalyzer can be installed directly from the ostorlab agent store or built from this repository.

 ### Install directly from ostorlab agent store

 ```shell
 ostorlab agent install agent/ostorlab/wappalyzer
 ```

You can then run the agent with the following command:

```shell
ostorlab scan run --agent agent/ostorlab/wappalyzer domain-name tesla.com
```


### Build directly from the repository

 1. To build the wappalyzer agent you need to have [ostorlab](https://pypi.org/project/ostorlab/) installed in your machine.  if you have already installed ostorlab, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_wappalyzer.git && cd agent_wappalyzer
```

 3. Build the agent image using ostorlab cli.

 ```shell
 ostortlab agent build --file=ostorlab.yaml
 ```
 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 1. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
	  ```shell
	  ostorlab scan run --agent agent//wappalyzer domain-name tesla.com
	  ```
	 * If you specified an organization when building the image:
	  ```shell
	  ostorlab scan run --agent agent/[ORGANIZATION]/wappalyzer domain-name tesla.com
	  ```


## License
[Apache-2](./LICENSE)

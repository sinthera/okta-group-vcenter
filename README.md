# Okta groups and members to vCenter through APIs and SCIM

This Python script handles some basics user and group operations into a vCenter from Okta source. It interacts with Okta and vCenter through the [Okta API](https://developer.okta.com/docs/reference/core-okta-api/) and through the [vCenter SCIM API](https://developer.broadcom.com/xapis/vmware-identity-broker/latest/scim2/), using HTTP requests exclusively for managing user and group operations. The admitted operations are 3:
1. Syncing group members from Okta to vCenter - create or delete user where is necessary;
2. Create vCenter group;
3. Delete vCenter group;
   
Additionally, the script logs events and errors for monitoring purposes.


## Installation

1. Clone the repository

### Create a service app in Okta
Follow this guide: https://developer.okta.com/docs/reference/rest/#create-a-service-app-in-okta

1. At the guide point n.5 make note of the `Client ID` listed in the **Client Credentials** section;
2. At the guide point n.7 pay attention to grant the `okta.group.read` scope to the app;
3. At the guide point n.8 click **Copy to clipboard** to copy the private key in **PEM** format, optionally paste the key into `private_key.pem` file of the repo;
4. Save the `Client ID`, the `Okta host` and the private key `path` to the `.env` file;

### Create vCenter Bearer Token
Follow this guide: https://iamse.blog/2023/04/25/enable-okta-for-vmware-vcenter-server/

1. Follow only the step 2 of the guide and save the `bearer token` and the `vcsa host` in the `.env` file

### Install and set up the environment
1. Install python3 on the system, for instance in Ubuntu 22.04:
```bash
sudo apt update
sudo apt install python3
```

2. Create the virtual environment and activate it:
```bash
 python3 -m venv venv
 source venv/bin/activate
```

3. Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the requirements in the virtual environment. Install pip, for instance in Ubuntu 22.02:
```bash
python -m ensurepip --upgrade
```

4. Then install all the libraries:
```bash
pip install -r requirements.txt
```

## Usage

Run the following command to start:
```bash
source venv/bin/activate
python3 main.py
```

Then enter '`1`', '`2`' or '`3`' to:
1. **Sync** the group from okta to vCenter. If some users missing in the vCenter group then create them, if some users are not in the okta group then delete them;
2. **Create** the group in vCenter;
3. **Delete** the group in vCenter;
   
Now enter the `group name` case insensitive to process.

Alternative Usage:
```bash
python3 main.py  --sync | --create | --delete GROUPNAME
```
Note:

Only one of --sync, --create, or --delete can be used at a time.
GROUPNAME is a required positional argument representing the name of the group to be processed.

For more details, run: 
```bash
python3 main.py --help
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)
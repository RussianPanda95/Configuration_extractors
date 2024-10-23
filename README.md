### Configuration_extractors

Unless otherwise indicated, the samples mentioned can be found in MalwareBazaar or VirusTotal.

#### DcRAT:

The configuration extractor was tested on the following samples:

_a2766b20b3d09b2eee3a9805cffef7228dc2eab1265a6fbc1e98f67105ae51b9 da642fc983f09b106c32181f7e66d0cad426924650594ca613e5ce5b25b71493 4530c2681887c0748cc2ecddb1976d15ad813a4a01e5810fd8b843adcd2fd3d0_

#### DynamicRAT:

The configuration extractor was tested on the following samples:

_41a037f09bf41b5cb1ca453289e6ca961d61cd96eeefb1b5bbf153612396d919
856a3df5b1930c1fcd5fdce56624f6f26a7e829ea331a182b4a28fd2707436f1
b2a3112be417feb4f7c3b3f0385bdaee9213bf9cdc82136c05ebebb835c19a65_

#### IcedID First Stage Configuration Extractor:

The configuration extractor was tested on the following samples:

_8fc683128de2f77baddeff88b5fb427c70f9f099cd293032d780e3e06b6f947b
fd37c98782453214bab6484f6045b796a5a3dc7ebba9a894f6783817eef6c9c7
dd651c2ffe94faf59e3a3db2da56e05a1a12fcae7cd5f87881d1cb036be3ec2a 59b1721e3c3a42079673bebeb36e8c47dad88e93bdebcd6bb1468c4ca1235732_

All samples can be found on https://www.unpac.me/

#### LummaStealer:
The configuration extractor was tested on the following samples:
_988f54f9694dd1ae701bacec3b83c752_

#### MetaStealer:

The configuration extractor was tested on the following samples:
_5f690cddc7610b8d4aeb85b82979f326373674f9f4032ee214a65758f4e479be_

#### RemcosRAT:

The configuration extractor was tested on the following samples:

_63a2dcb487d0d875688f4e4d5251a93b 2734bb37c9994c543ea81e33a79384053a4635fe7b2f1c8d3fe78d6640b7de9a_

#### Poseidon Stealer:
The configuration extractor was tested on the following samples:

_935bab8750187b584e23fb8a522200bcdf526db3c7ece0c6e909ee6e48f4321f_

#### Vidar Stealer:

The configuration extractor was tested on the following samples:

_37c74886ce85682039bced4a6423e233aebd962921d9a76008d19ff75483a52c
6956fb2dd65d6627c23b680d4149983017bcb8e8b8fc1d30a5210998ca8cf801
3a7512884d5e269a6c9d74a0af38c0d4d4b95bdbe5c7cc8d8608e84a725d2134
bd6370870671ccc61bb9a7ae5d31abc446e893dce15eeaff13deeb64f9317926
ed28af0855aa6e00776f3633c15663e4a930f54ac399b48369f485e31250849b
b30bdc75d85cac464fcc59df6a1db4c7ca19c93c2b42db961b41fd814c230d80
505e21494deb4e828da8bdfa386fa59a2599f89dc87276f25bd6d923aed13f83
eba331ce626b9c6ca338c439b608d5234bfd0d0d5408de9e8b64e131435e4216_

#### WhiteSnake Stealer - XOR:

The configuration extractor was tested on the following samples:

_f7b02278a2310a2657dcca702188af461ce8450dc0c5bced802773ca8eab6f50
c219beaecc91df9265574eea6e9d866c224549b7f41cdda7e85015f4ae99b7c7_

### Extractor Usage
Ensure you have all the [appropriate Python packages](./requirements.txt) installed on your host before running the extractors.

**Note: If running on a Linux system, ensure to install mono and dnlib**

#### Directly via Python

`python <python_extractor_path> <sample_path>`

#### Using the [MACO](https://github.com/CybercentreCanada/maco) CLI

Since the extractors have been ported to the MACO extractor framework, you can run extractors by:

`maco <python_extractor_path_or_directory> <sample_path>`

#### Using [ConfigExtractor-py](https://github.com/CybercentreCanada/configextractor-py) CLI (Supports MACO extractors)

`cx <python_extractor_path_or_directory> <sample_path>`

# WordPress Bruteforce Scanner and CSF AutoBlocker


NodeJS Application that scans an apache log and takes action on bad requests based on request counts.", "main": "wp-login-auto-block.js"

## Installation

``$ git clone https://github.com/snxraven/wordpress-bruteforce-scanner-and-csf-autoblocker.git``

``$ cd wordpress-bruteforce-scanner-and-csf-autoblocker``

``$ npm i``

``$ cp default.env .env``

``$ nano .env``

You will need edit your .env file to match the log you would like to watch as well as the count you would like to block at.

## Usage

``$ node wp-login-auto-block.js``

## Linux Compilation
This can be compiled into a linux binary file using nexe, no special configuration required. 

To compile this app without the need of NodeJS to be installed on the machine for use run the following:

`` $ npm i nexe``

`` $ nexe wp-login-auto-block.js``

You will then see your new binary file "wp-login-auto-block"



## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)

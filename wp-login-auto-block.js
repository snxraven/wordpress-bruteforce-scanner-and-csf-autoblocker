// Wordpress WP-Login Brutce Force RealTime CSF Utility
// Written by: SNXRaven - 2021

// Use Tail NPM to follow the log in question
Tail = require('tail').Tail;
// Use dotenv NPM to allow .env file
require('dotenv').config()
// Set how many requets to block an IP. Read from .env "BLOCK_ON_COUNT"
let blockOn = process.env.BLOCK_ON_COUNT
// Tell tail which log file to watch
tail = new Tail(process.env.MAINLOG_FILE);

// Set up CMD interface to run CSF commands
const cmd = require('cmd-promise')

// Setting up our main storage logic - for now this program does not use a database system.
let serverStatusCount = 0;
let attackData = []
let blockedIPs = []
let ipToBlock

// Let start
console.log("Default looking at access_log in wordpress attack mode\n Searching for WP-LOGIN REQUESTS")

// When tail sees a new line, start processing the data
tail.on("line", function (data) {
  // Convert Data to String
  let requestInfo = data.toString()
  // FIND IP Address from this request
  var ipRegEx = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/; // RegEx IPAddress Format
  var ipRegExMatched = requestInfo.match(ipRegEx); // Set up our match
  let remoteIP = ipRegExMatched[0] // Set our var

  // Grab the whitelist
  let whitelistData = process.env.WHITELIST
  let whitelist = whitelistData.split(",")

  // If an IP is found to be in the whitelist, return as to do nothing. 
  for (const [key, value] of Object.entries(whitelist)) {
    if (value === remoteIP) return
  }

  // Filtering out any server-status requests - These are annoying. 
  if (requestInfo.includes("server-status")) {
    // Add to the server status count so we may keep track of these requests. 
    serverStatusCount++
    // Lets return the data as no not proceed with any further code, as it is not needed.
    // We return to stdout here to update the cli without adding a new line line a clock
    return process.stdout.write("Server Status Count: " + serverStatusCount + "\r");
  }

  // If request contans wp-login lets process its request
  if (requestInfo.includes("wp-login.php")) {
    // Lets start the process of logging attack attempts to determine request intent.
    // Over the threshhold here will automatically CSF D the IP Address.
    // In this simple version, we will just log each IP Address as they come in within an array
    // We will then roll and count this array after each detection to determine the IPs intent.
    console.log("WP LOGIN REQUEST DETECTED!\n---------")
    console.log(data + "\n----------");
    attackData.push(remoteIP)

    // Lets count the attack data per IP Address to ensure its logged properly.
    var counts = {};

    // For each IP Address recorded into the main attackData array, count them and see outmany bad requests they have made.
    attackData.forEach(function (x) {
      // Add a point for each entry
      counts[x] = (counts[x] || 0) + 1;
      // 
      for ([key, value] of Object.entries(counts)) {
        // If the count has hit the blockON Count we start the blocking process

        if (counts[x] == blockOn) {
          // Preserve the key for later blocklist addition
          ipToBlock = key

          // Check the already blocked IPs - If the remoteIP is in the list do nothing
          if (blockedIPs.includes(key)) {
            return

          } else {
            // The remoteIP is not listed, lets add it.
            blockedIPs.push(ipToBlock)
            // Let the log know we are blocking the IP
            console.log("Starting to block bad IP")
            // Run the block, wait for the promise - Requests are still going on
            cmd(`csf -d ` + key + " WP-Login Brute Force Blocked Via WPBruteForceScanner").then(out => {
              console.log('CSF Reply: ', out.stdout)
              // The block has finished - remoteIP no longer has access
            }).catch(err => {
              // IF we see an error, give its output
              console.log('CSF Error: ', err)
            }).then(out2 => {
              // Set IPBLOCK to null for a reset and start scanning for new attacks
              ipToBlock = null;
              console.log("Attack Stopped, Looking for new attacks....")
            })
          }
        }
      }

    });

    // Live view of the counts
    console.log(counts)

  } else {
    // This section is real site traffic, you can console.log(data) to see the apache log output of each request if wanted.    

  }

});

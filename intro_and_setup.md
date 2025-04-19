# Intro to the Workshop
- This is the first performance of this all for us :cold_sweat:
- It is a full knowledge / whitebox exercise
- Aim is to demonstrate the workflow of a threat informed purple team exercise from CTI to red to blue to identifying improvements
- The workshop will start with setting the context with CTI, then we'll have three blocks of emulation, verification and table top and we'll finish with the findings of the exercise
- If you have questions or run into problems ask the moderators/facilitators for help

# How to Work in your Table Team
- You can follow along either the Google meeting screen share of the moderator or the one you/your table mates share in your break-out room
- CTI, red and blue labs are all demonstrated by the moderator and you can follow along
- TTX will be explained by the moderators, you'll get additional material and then you will do the exercise with your table team
- Where possible you can split/spread the work among your table mates but we suggest to still work in pairs
- Please actively participate, share, help, communicate for maximum value and fun :tada:

## Setup
- You will get pop-ups, offers to take a Splunk tour or upgrade Enterprise Security and error messages - just klick them "away"
- The exercise will be done in Splunk Attack Range (SAR) hosted in AWS which consists of the attacked environment, a Kali Linux VM and a Splunk VM
- We have one SAR instance per table so you will need to coordinate some steps during emulation to not produce conflicts
- All activities can be performed using your browser

### Internet Connection
- Who is using his own mobile phone tethering to connect to the Internet?
  - Please copy your IP from https://www.whatsmyip.org
  - And fill it along with your (first) name in the corresponding field in this [Google sheet](https://docs.google.com/spreadsheets/d/1Mq08oPex0Z1XPtCl6rPqtSVbonF_1UozHA_6ncfj4zs/edit?usp=share_link)
- If you are connecting via the guest WLAN please connect now, the details can be found on the table info page

### Google Meeting
- Open the Google meeting in your browser, the details can be found on the table info page
- Mute your mic since we'll be only using it with people in the room
- Familiarize yourself how to
  - Join/leave the breakout room of your table
  - Share/unshare your screen

### Access Guacamole
- Open the link to Guacamole and log in, the details can be found on the table info page
- Click on KALI-VNC, this will be the only connection you will use, the rest are there for debugging
- The session to Kali can be shared among all participants but we still recommend to use Google meeting to share the screen
- Connections to Windows can't be shared so you'll kick out the previous user
- Familiarize yourself with the somewhat trick copy & paste procedure, the details can be found on the table info page
- Use browser "back" to exit to the Guacamole startpage
- Copy and paste from your laptop is done by binging up the "menu" on the left of the screen by pressing `Shift` + `Ctrl` + `Alt`
  - Then use your laptops regular copa and paste key combo to copy/paste to/from the text field called `Clipboard`
  - After that you can use `Ctrl` + `Shift` `c` or `v` for the Kali VM
  - Or `Ctrl` + `c`or `v` for the Windows VMs
  - Press `Shift` + `Ctrl` + `Alt` again to hide the menu again and return to the desktop
- As an alternative you can also use https://yopad.eu to transfer the commands between your computer and the lab VMs
- If you experience issues with typing special characters like `\` or `|` use the on-screen keyboard of the target VM

### Access Splunk
- Open the link to Splunk and log in, the details can be found on the table info page
- Splunk can be used by all participants concurrently

### Access Workshop Documentation
- Open the link to the [workshop repository](https://github.com/tscomm99/purple-team-workshop-2024)
- Log in if you are not already
- You will be using the material in the repo throughout the workshop so please keep it open

### Access Workshop Google Share
- Open the link to [Google Drive](https://drive.google.com/drive/folders/1dsrycoWPXzC-JB-ZamZ7EHxlOU5Fvq_J?usp=sharing)
- Log in if you are not already
- Navigate to the sub folder of your table
- You will be using the material in the drive throughout the workshop so please keep it open

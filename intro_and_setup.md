# Intro to the Workshop
- It is a full knowledge / whitebox exercise
- Aim is to demonstrate the workflow of a threat informed purple team exercise from CTI to red to blue to identifying improvements
- If you have questions or run into problems ask the moderators/facilitators for help

# How to Work in your Table Team
- You can follow along either in the meeting screen share of the moderator or the one you/your table mates share in your break-out room/meeting
- CTI, red and blue labs are all demonstrated by the moderator and you can follow along
- TTX will be explained by the moderators, you'll get additional material and then you will do the exercise with your table team
- Where possible you can split/spread the work among your table mates but we suggest to still work in pairs
- Please actively participate, share, help, communicate for maximum value and fun :tada:

### Teams Meeting
- Open the Teams meeting in your browser using the information provided by the workshop team
- Mute your mic since we'll be only using it with people in the room
- If necessary, familiarize yourself how to
  - Join/leave the breakout room or separate meeting of your table
  - Share/unshare your screen

## Setup
- You will get pop-ups, offers to take a Splunk tour or upgrade Enterprise Security and error messages - just klick them "away"
- The exercise will be done in Splunk Attack Range (SAR) hosted in AWS which consists of the attacked environment, a Kali Linux VM and a Splunk VM
- We have one SAR instance per table so you will need to coordinate some steps during emulation to not produce conflicts
- All activities can be performed using your browser

### Open the Workshop Repo on Github
- Please open the URL https://github.com/tscomm99/purple-team-workshop-2025-01
- Navigate to Introduction and Setup (or open intro_and_setup.md)
- Log in if you are not already
- You will be using the material in the repo throughout the workshop so please keep it open

### Internet Connection
- Who is using his own mobile phone tethering to connect to the Internet?
  - Please copy your IP from https://www.whatsmyip.org
  - And fill it along with your (first) name in the corresponding field in this [Google sheet](https://docs.google.com/spreadsheets/d/19Qvg4-iVPGrZ5CDWJv2WlZH05fmtjPEwtrhv6maUOro/edit?usp=drive_link)
- If you are connecting via the guest WLAN please connect now, the details can be found on the table info page

### Access Workshop Google Share
- Open the link to [Google Drive](https://drive.google.com/drive/folders/1buR-qCIkuns5KoQstblG_4lHHnHhCTZn?usp=sharing)
- Log in if you are not already
- Navigate to the sub folder of your table

### Access Guacamole
- Open the link to Guacamole and log in using the information provided by the workshop team
- Click on KALI-VNC, this will be the only connection you will use, the rest are there for debugging
- The session to Kali can be shared among all participants but we still recommend to use the meeting to share the screen
- Connections to Windows can't be shared so you'll kick out the previous user
- Use browser "back" button to return to the Guacamole start page
- If you experience issues with typing special characters like `\` or `|` use the on-screen keyboard of the target VM

### Copy & Paste for the Emulation Lab
#### Recommended Option
- Double-click StartHere.html placed on the Kali desktop which will redirect you to the workshop content on github so you can copy it from there
- If necessary StartHere.html is also available on each Windows system under c:\Temp
- After that you can use `Ctrl` + `Shift` `c` or `v` for the Kali VM
 - Or `Ctrl` + `c`or `v` for the Windows VMs
#### Alternative Copy & Paste Methods
- Copy and paste from your laptop to the Guacamole active session is done by bringing up the "menu" on the left of the screen by pressing `Shift` + `Ctrl` + `Alt`
  - Then use your laptops regular copy and paste key combo to copy/paste to/from the text field called `Clipboard`
  - After that you can use `Ctrl` + `Shift` `c` or `v` for the Kali VM
  - Or `Ctrl` + `c`or `v` for the Windows VMs
  - Press `Shift` + `Ctrl` + `Alt` again to hide the menu again and return to the desktop
- As a second alternative you can also use https://yopad.eu to transfer the commands between your computer and the lab VMs

### Access Splunk
- Open the link to Splunk and log in using the information provided by the workshop team
- Splunk can be used by all participants concurrently
- You will be using the material in the drive throughout the workshop so please keep it open

### Detailed Intro from each Workshop Track
- CTI
- Red emulation
- Blue verification
- Table top exercise

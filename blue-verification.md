# Verification of Detections and Preventions

In our workshop we're focusing on the detection side since our preventive posture is very "lean". In regular purple team
exercises you will also have much more findings on preventive controls and also much more interaction between preventive
controls and emulation actions during planning as well as execution.

But you may still come across some general findings on preventions. So please take a note of them wile you go through the exercise
so we can discuss them in the findings section at the end of the workshop.

As for high-level preventive findings you'll probably also have such opservations regarding the detective controls. Please make
sure you record them as well for the discussion.

## Introduction and Preparation
- To perform this task you will be comparing the emulation actions performed to the detection posture
  - First you will look at all the actions that got detected by going through the Splunk notables and mapping them to the emulation
  - Second you will be going through the undetected emulation steps and check if there is no detection in place or if it did not trigger
  - As bonus task you can try to find out why it did not trigger and how good the detection quality is for those that triggered
- Open the necesssary reference material
  - Open the [detection reference](resources/detection-reference.md)
  - Open the [emulation reference](resources/emulation-reference.md)
- Prepare the documentation for the verification
  - Navigate to your table's subdirectory on [Google Drive](https://drive.google.com/drive/folders/1dsrycoWPXzC-JB-ZamZ7EHxlOU5Fvq_J?usp=sharing)
  - Create an new text document
  - Copy the visible contents (not the raw markdown) of the [emulation reference](resources/emulation-reference.md) and paste them into the new text document
  - You can copy all parts into one document or create one document per emulation part
  - This will be the place to track and document your verification as well as record any high-level findings you may have

## Splunk Preparation and Hints
- To do the verification in the Splunk web UI
  - Log in
  - Navigate to `Apps` > `Enterprise Security` > `Incident Review`
- Optimize the displayed columns in the `Notables` table
  - Click on the gear wheel symbol at the right above the header row of the `Notables` table
  - In the pop-up remove the "Risk ..." and add "Annotations"
  - Click `Apply`
- To keep better overview we recommend to use new tabs for links in the Splunk UI
- To distinguish new from previous notables you can assign the reviewed ones the status "Closed" or "Part <n>" to map them to the corresponding part of the emulation
  - In `Incident Review` filter the notables if necessary
  - Select the ones you want to close, click `Edit Selected` and change `Status` to e.g. `Closed` in the `Edit Events` pop-up
  - Now you can filter the closed by clicking on the column header `Status` and de-select `Closed` from the statuses to be displayed
- An alternative way is to explicitly set a time frame
  - Click on the drop-down menu labeled with the chosen time frame, by default `Last 24 hours`
  - Specify the relative or absolute time frame
- Get a list of all relevant Splunk detections
  - Go to `Apps` > `Enterprise Security` then select `Configure` > `Content` > `Content Management`
  - Filter on `.yml`
- Open an saved search from the notables table in `Incident Review`
  - Expand the notable by clicking on the `>` icon in the column `i`
  - In the right half under `Correlation Search` click the link `Threat - ...yml - Rule` (opens in a new tab automatically)
- Perform a manual search
  - Go to `Apps` > `Search & Reporting` (you may want to open that in a new tab)
  - Set the desired time frame by clicking on the pop-up menu labeled `Last 24 hours`
  - Enter a search expression
  - Hint: As a good practice you should always narrow the amount of data you want to search, for our workshop preceed each search with `index=win` unless there is `source=` at the beginning of the search
  - Hint: If you want to understand why a detection did not match it my be helpful to make the corresponding search expression more generic to find out if there is any of the expected data present
- If you have multiple detections or multiple emulation steps with the same technique in the notables table
  - Check the name of the detection `....yml` for hints
  - Check the search expression or the URL to the Sigma HQ yml file which is the source of the detection rule
  - Expand the notable line by clicking on `>`
  - Check the left side `Additional detils`
  - Check the contents of `Original Event` on the right half
  - The data after `<Data Name='CommandLine'>` contains the command line executed



## Procedure for Analysing Emulation Part 1-3

### Notables from the Emulation

- After emulation part 1 you should have these new [notables](resources/Incident_Review_Part_1_Splunk.pdf)
- After emulation part 2 you should have these new [notables](resources/Incident_Review_Part_2_Splunk.pdf)
- After emulation part 3 you should have these new [notables](resources/Incident_Review_Part_3_Splunk.pdf)

### Collect and Document Findings of Red Team Steps Execution
  - Were there any?

### Possible Findings of this Verification

- Technique without a detection
- Technique with a detection that did not trigger (incorrect detection search, required data not created/forwarded/indexed correctly)
- Misalignment of detection and emulation technique selection
- Detection which did not detect all executed procedures or other detection quality issues

### Workflow to Verify Detections
- In Splunk `Incident Review` go through the notables one by one
- Record your findings from the questions below in the verification sheet you created
- Take a note of the techniques the detection triggering the notable contains
  - Either expand the notable line or
  - If enabled - note them from the column `Annotations`
- Check if/where you can find  the referenced techniques in the verification sheet you prepared based on the emulation reference
  - Is it mapped to the correct emulation step?
  - Were all the emulation steps mapped to the technique detected?
  - Do the techniques of the emulation match with those of the detection?
- If the detection technique does not match any technique of the emulation
  - Search the emulation reference for keywords from the detection (refer to the description and the search expression for details)
- If an emulation step was not detected after processing all the notables
  - Search the [detection reference](resources/detection-reference.md) for keywords of the emulation step, the techniques specicied or review the .yml files for possible searches that did not trigger
  - Search Splunk for the performed emulation action e.g. `index=win whoami` to understand if and what data you get from the victim endpoints
- Bonus task if you finish early
  - Review the Splunk searches and the references and get an opinion how "good" the detection is

### Possible Analysis Results :rotating_light: Spoiler Alert! :rotating_light:

- After analysing part 1 you could have these [findings](resources/Blue_Analysis_Part_1.pdf)
- After analysing part 2 you could have these [findings](resources/Blue_Analysis_Part_2.pdf)
- After analysing part 3 you could have these [findings](resources/Blue_Analysis_Part_3.pdf)

## Analysis Summary :rotating_light: Spoiler Alert! :rotating_light:
- Detections that are [configured vs. that triggered](resources/cti/purple/configured_vs_triggered.json)
- Detections that [triggered and are used by Black Basta](resources/cti/purple/black_basta_detection_coverage.json)

## More Ways to Leverage ATT&CK

### Preventive Posture
- MITRE Engenuity Evaluations https://attackevals.mitre-engenuity.org
- D3FEND https://d3fend.mitre.org
- ATT&CK Mitigations https://attack.mitre.org/mitigations/enterprise/
- Mappings Explorer https://center-for-threat-informed-defense.github.io/mappings-explorer/

### Detection Posture
- MITRE CAR https://car.mitre.org
- ATT&CK DataSources https://attack.mitre.org/datasources/
- Top Techniques https://top-attack-techniques.mitre-engenuity.org/

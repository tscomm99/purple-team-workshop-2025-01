# Verification of Detections and Preventions

In our workshop we're focusing on the detection side since our preventive posture is very "lean". In regular purple team
exercises you will also have much more findings on preventive controls and also much more interaction between preventive
controls and emulation actions during planning as well as execution.

But you may still come across some general findings on preventions. So please take a note of them while you go through the exercise
so we can discuss them at the end of this workshop section.

As for high-level preventive findings you'll probably also have such observations regarding the detective controls. Please make
sure you record them as well for the discussion.

## Introduction and Preparation
- Open the necesssary reference material
  - Open the [detection reference](resources/detection-reference.md)
  - Open the [emulation reference](resources/emulation-reference.md)
- Prepare the documentation for the verification
  - Navigate to your table's subdirectory on [Google Drive](https://drive.google.com/drive/folders/1vgt2CnNr_iRbZpUD5jNu2JX2WpRNgITr?usp=sharing)
  - Open the detection verfication document we prepared for you
  - This will be the place to track and document your verification as well as record any high-level findings you may have

### Splunk Preparation and Hints
- First, a little refresher on Splunk :snowflake: :snowflake: :snowflake:
- To do the verification in the Splunk web UI
  - Log in
  - Navigate to `Apps` > `Enterprise Security` > `Incident Review`
- Optimize the displayed columns in the `Notables` table
  - Click on the gear wheel symbol at the right above the header row of the `Notables` table
  - In the pop-up remove the "Risk ..." and add "Annotations"
  - Click `Apply`
- To keep better overview we recommend to use new tabs for links in the Splunk UI
- To distinguish new from previous notables you can assign the reviewed ones the status "Closed" or "Part ..." to map them to the corresponding part of the emulation
  - In `Incident Review` filter the notables if necessary
  - Select the ones you want to close, click `Edit Selected` and change `Status` to e.g. `Closed` in the `Edit Events` pop-up
  - Now you can filter the closed by clicking on the column header `Status` and de-select `Closed` from the statuses to be displayed
- An alternative way is to explicitly set a time frame
  - Click on the drop-down menu labeled with the chosen time frame, by default `Last 24 hours`
  - Specify the relative or absolute time frame
- Get a list of all relevant Splunk detections
  - Go to `Apps` > `Enterprise Security` then select `Configure` > `Content` > `Content Management`
  - Filter on `.yml`
- Open a saved search from the notables table in `Incident Review`
  - Expand the notable by clicking on the `>` icon in the column `i`
  - In the right half under `Correlation Search` click the link `Threat - ...yml - Rule` (opens in a new tab automatically)
- Perform a manual search
  - Go to `Apps` > `Search & Reporting` (you may want to open that in a new tab)
  - Set the desired time frame by clicking on the pop-up menu labeled `Last 24 hours`
  - Enter a search expression
  - Hint: As a good practice you should always narrow the amount of data you want to search, for our workshop preceed each search with `index=win` unless there is `source=` at the beginning of the search
  - Hint: If you want to understand why a detection did not match it may be helpful to make the corresponding search expression more generic to find out if there is any of the expected data present
- If you have multiple detections or multiple emulation steps with the same technique in the notables table
  - Check the name of the detection `....yml` for hints
  - Check the search expression or the URL to the Sigma HQ yml file which is the source of the detection rule
  - Expand the notable line by clicking on `>`
  - Check the left side `Additional details`
  - Check the contents of `Original Event` on the right half
  - The data after `<Data Name='CommandLine'>` contains the command line executed

### Notables from the Emulation

In case your emulation did not go well you can consult the PDFs below but you will not be able to drill down into the details of the detection match.

- After emulation part 1 you should have these new [notables](resources/Incident_Review_Part_1_Splunk.pdf)
- After emulation part 2 you should have these new [notables](resources/Incident_Review_Part_2_Splunk.pdf)

## Procedure for Analysing Emulation Part 1&2

To conduct the verification look at the emulation flow and try to match each step performed to a Splunk notable. Write down all your observations in the Google document we prepared for you.

**Note**: Don't get confused if the sequence of the Splunk detections/notables is not 100% aligned with the emulation, Splunk is configured to run all detections searches in batches every 5'

To perform this task go through each emulation step chronologically and do the following:

- Check if you find a notable/triggered detection that matches the host, time and action performed in the emulation
  - If so, write down the detection rules/searches that triggered and
    - Which ATT&CK technique ID does the detection list, note the ones that do not match with the ones listed in the emulation (this is important to make the ATT&CK gap analysis)
  - If not, perform an open search for a/some good identifying string/s (e.g. quser) of the emulation step
    - If you get no search results - no luck :sob: to fix this you need to collect additional data or even add/improve tooling to monitor it
    - If you get search results
        - check if we have a detection that did not get triggered and take a note
            - Search for a significant term e.g. quser.exe in the Splunk ES configuration > content management
            - Test the detection by copying the search expression into the manual search
        - if we have no failed detection note what could be used in the data we collected in Splunk
- Bonus (TBD provide good example steps)
    - Check if you can find a detection for an undetected step in the SIGMA repo
    - Check if you can find out why the detection in place did not trigger
        - Check the syntax of the detection and compare it to the data

### Possible Findings of this Verification

- Technique without a detection
- Technique with a detection that did not trigger (incorrect detection search, required data not created/forwarded/indexed correctly)
- Misalignment of detection and emulation technique selection
- Detection which did not detect all executed procedures or other detection quality issues

### Possible Analysis Results :rotating_light: Spoiler Alert! :rotating_light:

- After analysing you could have these [findings](resources/Detection_Verification_Completed.pdf)

## Analysis Summary
- Detections that are [configured vs. that triggered](resources/cti/purple/configured_vs_triggered.json)
- Detections that [triggered and are used by Black Basta](resources/cti/purple/black_basta_detection_coverage.json)

..or open them directly in [Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2Ftscomm99%2Fpurple-team-workshop-2025-01%2Frefs%2Fheads%2Fmain%2Fresources%2Fcti%2Fpurple%2Fconfigured_vs_triggered.json&layerURL=https%3A%2F%2Fraw.githubusercontent.com%2Ftscomm99%2Fpurple-team-workshop-2025-01%2Frefs%2Fheads%2Fmain%2Fresources%2Fcti%2Fpurple%2Fblack_basta_detection_coverage.json)

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

# Gateway Reports for Android

This Android app fetches live IDS reports from the Raspberry Pi and runs Llama 3.2 1B Instruct with ExecuTorch on the phone. See the [integration guide](../PHONE_INTEGRATION.md) for Pi setup and the hardware acceptance test.

## Build

Open this `android` folder in Android Studio. Install SDK Platform 35 and select JDK 17 for Gradle. Use the included Gradle 8.9 wrapper. Sync Gradle, select your USB-connected phone and run the **debug** variant. The CLI equivalent for building the APK is `./gradlew :app:assembleDebug`. The debug build uses plain HTTP for the trusted lab network.

Keep your previous debug signing key to update your existing install and retain its local model files. To provision the tested Instruct model on a debug install, place the matching `Llama-3.2-1B-Instruct.pte` and `tokenizer-instruct.model` in `/data/local/tmp/llama` on your USB-connected phone, then run `bash prepare-model.sh instruct` from this folder. The script copies the pair into app-private storage. Model weights are separate from the source archive.

## Synthetic samples

The app opens with bundled samples. For the original network demo, run `python3 pi/demo_api.py --host <Pi-LAN-IP> --port 8080` from this folder, with the live report feed stopped. The client tries `/v1/reports` first and tries `/demo/reports` only after a 404. The synthetic server always serves the bundled fixture. Use **Fetch reports** and look for **Fetched from Pi · Synthetic**.

For live results follow the integration guide and look for **Fetched from Pi · Live IDS**. Reports on the currently open screen can be explained without Wi‑Fi. A fresh app launch loads the bundled samples.

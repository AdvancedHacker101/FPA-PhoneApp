# FPA-PhoneApp
This is a phone application for FPA or *Fingerprint Authentication*  
This is where your authentication keys/credentials will be stored.  
You can use this application to authenticate to services with your fingerprint.  
Some of the *services* you can authenticate to include:  
* Windows itself
* Any website
Also planning to add **2FA** support for website owners, so you can login, then use your fingerprint as a 2nd factor.  
I belive this gives you a lot of security, as well as privacy, because passwords are stored on your phone, not in your browser directly.  
## Installation
This application is in development stage, so regular users may check back later for using this application. But you're feel free to install it on your phone.  
Follow the instructions:  
1. Fork the project and load it into android studio
2. Connect your debugging mode enabled device to your PC
3. Press the green `Run` button on the top and select your phone from the dialog that pops up

That's it, the application is now running on your phone!
## Usage
There isn't much to do here, you can `wipe the database` (for debugging purposes), and `Detect QR Code`.  
You will be using the QR Code button a lot. When the [Native App](https://github.com/AdvancedHacker101/FPA-NativeApp) shows a QR Code, you need to scan it.  
After scanning the QR Code a dialog pops up and says *waiting for operations to complete*.  
In this stage the application is communicating with the [Native App](https://github.com/AdvancedHacker101/FPA-NativeApp) over the network.  
When the connection is ready, you will be prompted to touch the fingerprint sensor.  
You can touch the sensor, or cancel the operation.  
Don't worry if your fingerprint isn't detected right the first time, the dialog stays until a successful authentication or pressing cancel.  
After that the other components of the application handle the rest of the work, you can put the phone down.  
## Development Notes
* Whenever keys/credentials doesn't match you should use the wipe database option on the phone, and you should remove the key on the other application component.  
* Network Connection is required, but internet isn't.  
* Fingerprint Sensor is obviously required :)

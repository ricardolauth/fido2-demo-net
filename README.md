# fido2-demo-net
This repository implements a fido2 authentication for demo purpose.
It makes use of the fido2 net lib to implement the authentication. 
After a sucessful authentication the server returns a basic bearer access token which can be used to make further request to the 
protected endpoints of the ME Controller.
Don't use this repository and it's architecture as a template for productive projects. 
It doesn'tt follow common best practices in many ways. 

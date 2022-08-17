# Spring-Security-Demo

Creating your own account:
- Use the 'BootstrapData' class and instantiate a user object with your desired credentials.

Logging in:
- Create a post request method to 'http://localhost:8080/login'
- Body type at the moment is x-www-formurlencoded.
- Include the following keys and values: 'username' and 'password'
  - The above has to be valid credentials or the response will be a 403 Forbidden.

Getting your access token: 
- The response after signing in with valid credentials will include a JSON response with two serialized objects.
- Copy the 'access_token' value. 

Using your access token to request from secure endpoints:
- Any endpoint within the 'UserController' is secured and needs a valid bearer token (encoded JWT) to authorize. 
- Within your requests to any of the endpoints, include a header 'Authorization', and the value for the header should be 'Bearer {access_token}'.
- You should now be able to make requests to any endpoints within the application with that bearer token.

General information:
- Database: H2 Embedded Instance
- A lot of the code was taken from a youtube tutorial, but I've made some changes as I deemed appropriate last night.
  - There still needs to be refactoring done to make requests, and responses facilitated by JSON amongst other things.
- As I said above, if your credentials are incorrect when attempting to login, you will get a 403 response. 
- If you try and make requests to any endpoints without a valid bearer token, you will get a 403 response.
- If you're interested as to how JWT's are encoded and what their purpose is, go to jwt.io and paste your access token
- Passwords are encrypted upon sending user information to the database.

*THIS IS JUST A DEMO, NONE OF THIS IMPLEMENTATION REPRESENTS ANYTHING I WOULD PUT INTO PRODUCTION.* 

The main goal of this project was to quickly demonstrate a working implementation of Spring Security, this does not consider best practices or design patterns by any means.



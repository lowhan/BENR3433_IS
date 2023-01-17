const MongoClient = require("mongodb").MongoClient; // MongoDB database
const Admin = require("./admin");                   // Import admin class
const jwt = require('jsonwebtoken');                // JWT token		
const express = require('express');                 // Express server
const app = express();  
const fetch = require('node-fetch');                
const { stringify } = require('querystring');       

// Connection to Database
MongoClient.connect( 
	//"mongodb://127.0.0.1:27017/?readPreference=primary&appname=MongoDB%20Compass&directConnection=true&ssl=false", 	// main DB for server
  //"mongodb://user:qwerty123@10.131.13.195:27017/?authSource=admin&readPreference=primary&directConnection=true&tls=true&tlsCAFile=C%3A%5CProgram+Files%5CMongoDB%5CServer%5C6.0%5Cbin%5Cmongodb3.pem&tlsAllowInvalidCertificates=true",
	//"mongodb://192.168.1.17",
  "mongodb://user:qwerty123@192.168.1.17:27017/?tls=true&tlsAllowInvalidHostnames=true&authMechanism=DEFAULT&authSource=admin&tlsCAFile=C%3A%5CProgram+Files%5CMongoDB%5CServer%5C6.0%5Cbin%5Cmongodb.pem",
  { useNewUrlParser: true },
).catch(err => {
	console.error(err.stack)
	process.exit(1)
}).then(async client => {
	console.log('Connected to MongoDB');
	Admin.injectDB(client);
})

const rateLimit = require('express-rate-limit')     // Limit the rate of sending request 
// rate limiter to allow user send request within specific number of requests.
const limiter = rateLimit({
	windowMs: 10 * 60 * 1000,     // 10 minutes
	max: 3,                       // Limit each IP to 3 requests per `window`
  message: {
    status: 429,
    success: false,
    msg: 'You are doing that too much. Please try again in 10 minutes.'
   },
	standardHeaders: true,        // Return rate limit info in the `RateLimit-*` headers
	legacyHeaders: false,         // Disable the `X-RateLimit-*` headers
})

app.use(express.static(__dirname + '/'));
app.use(express.json());

// HTML page is first sent to user
app.get('/', (_, res) => res.sendFile(__dirname + '/index.html'));

// Login function is made to let user to authenticate and authorise as a role using JWT token
app.post('/login',limiter, async (req, res) => {
  if (!req.body.captcha || req.body.captcha == undefined)      // if no captcha received
  {
    return res.json({ success: false, msg: 'Please select captcha' });
  }
    
  console.log(req.body);
  // Secret key
  const secretKey = '6LcpYfsjAAAAALODc8Cjksy5gb5xhpAygUwKtq1p';
  // Verify URL
  const query = stringify({
    secret: secretKey,
    response: req.body.captcha,
    remoteip: req.connection.remoteAddress
  });
  const verifyURL = `https://google.com/recaptcha/api/siteverify?${query}`;
  
  // Make a request to verifyURL
  const body = await fetch(verifyURL).then(res => res.json());
  console.log(body)
  // If unsuccessful
  if (body.success !== undefined && !body.success)
  {
      return res.json({ success: false, msg: 'Failed captcha verification' });
  }
  // If successful  
  else 
  {
    // Authentication 
    const admin = await Admin.loginadmin({"login_username":req.body.name ,"login_password": req.body.password });
    if (admin == "invalid username"|| admin =='invalid password')
	  {
		  return res.json({ success: false, msg: 'Invalid username/password' });
	  }
    else
    {
      // Generate token for authorization
      return res.status(200).json({
        token : generateAccessToken({								
            '_id': admin._id,
            'login_username' : admin.login_username,
            'login_password' : admin.login_password,     
            'security_name' : admin.security_name,
            'security_phonenumber' : admin.security_phonenumber,	
            'role' : admin.role
        }),
        msg : 'Login success',
        success: true
      })
    }
  }  
});

// View function is made and assume that the user could use the token to authorise as one of the role (like admin) to perform CRUD operations on specific documents.
app.post('/view', async (req, res) => {
  var verifiedtoken;        
  if(req.body.token == '')
  {
    return res.json({ success: false, msg: 'No token was inserted' });
  }
  else
  {
    // verify the content of the token
    verifiedtoken = AccessTokenVerify(req.body.token)  

    // If the given token has the authorize as admin
    // console.log(verifiedtoken);          
    if(verifiedtoken.role == 'admin')                  
    {
      let admin = await Admin.viewadmin(verifiedtoken);
      if(admin == "There is no such account")
      {
        return res.json({ success: false, msg: "There is no such account" });
      }
      else
      {
        return res.json({ success: true, msg: 'Valid token', result: JSON.stringify(admin)});
      }
    }
    else
    {
      return res.json({ success: false, msg: 'You have no permission/Invalid token' });
    }
  }  
});

app.listen(3000, () => console.log('Server started on port 3000'));

// JWT token - Used to prevent HTTP packets leaking the information between parties
function generateAccessToken(payload) {
  // set expire time duration (5 minutes)
	return jwt.sign(payload, "my-super-secret", {expiresIn: '5m'}); 
}

// JWT token - verify JWT token's content
function AccessTokenVerify(payload) {
  try {
    return jwt.verify(payload, "my-super-secret");
  }
  catch (err) {
    return err;
  }
}

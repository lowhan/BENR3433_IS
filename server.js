const MongoClient = require("mongodb").MongoClient;
const Admin = require("./admin");                   // Import admin class
const jwt = require('jsonwebtoken');                // JWT token		
const express = require('express');
const fetch = require('node-fetch');
const { stringify } = require('querystring');
const formidable = require('formidable');
var fs = require('fs');
const app = express();

// Connection to Database
MongoClient.connect( 
	"mongodb://127.0.0.1:27017/?readPreference=primary&appname=MongoDB%20Compass&directConnection=true&ssl=false", 	// main DB for server
  //"mongodb://user:qwerty123@10.131.13.195:27017/?authSource=admin&readPreference=primary&directConnection=true&tls=true&tlsCAFile=C%3A%5CProgram+Files%5CMongoDB%5CServer%5C6.0%5Cbin%5Cmongodb3.pem&tlsAllowInvalidCertificates=true",
	//"mongodb://192.168.1.17",
  { useNewUrlParser: true },
).catch(err => {
	console.error(err.stack)
	process.exit(1)
}).then(async client => {
	console.log('Connected to MongoDB');
	Admin.injectDB(client);
})

app.use(express.static(__dirname + '/'))
app.use(express.json());

app.get('/', (_, res) => res.sendFile(__dirname + '/index.html'));

app.post('/login', async (req, res) => {
  if (!req.body.captcha)      // if no captcha received
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

  // If not successful
  if (body.success !== undefined && !body.success)
  {
      return res.json({ success: false, msg: 'Failed captcha verification' });
  }
  else 
  {
    // If successful
    console.log(body)
    const admin = await Admin.loginadmin({"login_username":req.body.name ,"login_password": req.body.password });
    if (admin == "invalid username"|| admin =='invalid password')
	  {
		  return res.json({ success: false, msg: 'Invalid username/password' });
	  }
    else
    {
      return res.status(200).json({
        token : generateAccessToken({								// generate token for authentication, authorization
            '_id': admin._id,
            'login_username' : admin.login_username,
            'login_password' : admin.login_password,     
            'security_name' : admin.security_name,
            'security_phonenumber' : admin.security_phonenumber,	
            'role' : 'admin'
        }),
        msg : 'Login success',
        success: true
      })
    }
  }  
});

app.post('/view', async (req, res) => {
  //req.body = token
  var verifiedtoken;

  console.log(req.body);
  if(req.body.token == '')
  {
    return res.json({ success: false, msg: 'No token was inserted' });
  }
  else
  {
    verifiedtoken = AccessTokenVerify(req.body.token)
    console.log(verifiedtoken);
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

//File upload
app.get('/upload', (req, res) => {
  res.sendFile(__dirname + '/fileupload.html')
})

app.post('/upload', (req, res) => {
  var form = new formidable.IncomingForm()
  form.uploadDir = "./upload";
  form.keepExtensions = true;
  form.maxFieldsSize = 10 * 1024 * 1024;
  form.multiples = true;
  form.parse(req, function(err, fields, file) {
    let filepath = file.upload.filepath;
    let newpath = __dirname + '/upload/' + file.upload.originalFilename;
    fs.rename(filepath, newpath, function() {
      return res.json({ success: true, msg: "file uploaded" });
    });
  });
});

app.listen(3000, () => console.log('Server started on port 3000'));

//Used to prevent HTTP packets leaking the information between parties
//generate JWT token
function generateAccessToken(payload) {
	return jwt.sign(payload, "my-super-secret", {expiresIn: '1h'}); // set expire time duration
}
//verify JWT token's content
function AccessTokenVerify(payload) {
  try {
    return jwt.verify(payload, "my-super-secret");
  }
  catch (err) {
    return err;
  }
}


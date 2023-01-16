let admins;
const { hash } = require("bcrypt");
const bcrypt = require("bcryptjs")
const saltRounds = 10;

class Admin {
	static async injectDB(conn) {
		admins = await conn.db("VMS").collection("admins");
	}

    // login
    static async loginadmin(sample) { 											
		return admins.findOne({		//Check if username exists							
				'login_username': sample.login_username				
		}).then(async admin =>{
			if (admin) // Validate username
			{ 
				const PasswordValid = await bcrypt.compare(sample.login_password, admin.login_password)	// Validate password	 
				if (PasswordValid == false) 
				{
					return "invalid password";
				}
				else
				{
					return admin; // Return user object
				}
			}
			else // If admin doesn't exists
			{
				return "invalid username";
			}
		})
	}

	// read 
	static async viewadmin(token) {
		return admins.findOne({		//Check if username exists							
            'login_username': token.login_username,
            'login_password': token.login_password				
    }).then(async admin =>{
        console.log(admin);
        if (admin) // if user exists
        { 
            return admin;
        }
        else // If admin doesn't exists
        {
            return "There is no such account";
        }
        })
	}
}

module.exports = Admin;
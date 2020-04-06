const bcrypt = require("bcryptjs");
const usersCollection = require("../db")
  .db()
  .collection("users");

const validator = require("validator");

let User = function(data) {
  this.data = data;
  this.errors = [];
};

User.prototype.cleanUp = function() {
  if (typeof this.data.username != "string") {
    this.data.username = "";
  }
  if (typeof this.data.email != "string") {
    this.data.email = "";
  }
  if (typeof this.data.password != "string") {
    this.data.password = "";
  }
  // get rid of any bogus properties
  this.data = {
    username: this.data.username.trim().toLowerCase(),
    email: this.data.email.trim().toLowerCase(),
    password: this.data.password
  };
};

User.prototype.validate = function() {
  if (this.data.username == "") {
    this.errors.push("you must provide a username.");
  }
  if (
    this.data.username != "" &&
    !validator.isAlphanumeric(this.data.username)
  ) {
    this.errors.push("Username can only contains letters and numbers");
  }
  if (!validator.isEmail(this.data.email)) {
    this.errors.push("you must provide a email.");
  }
  if (this.data.password == "") {
    this.errors.push("you must provide a password.");
  }
  if (this.data.password.length > 0 && this.data.password.length < 4) {
    this.errors.push("Password must be atleast 12 Charachter");
  }
  if (this.data.password.length > 50) {
    this.errors.push("Password cannot exceed 50 Characters");
  }
  if (this.data.username.length > 0 && this.data.password.length < 3) {
    this.errors.push("Username must be below 12 Charachter");
  }
  if (this.data.password.length > 30) {
    this.errors.push("Username cannot exceed 30 Characters");
  }
};

User.prototype.login = function() {
  return new Promise((resolve, reject) => {
    this.cleanUp();
    usersCollection
      .findOne({ username: this.data.username })
      .then(attemptedUser => {
        if (
          attemptedUser &&
          bcrypt.compareSync(this.data.password, attemptedUser.password)
        ) {
          resolve("Congrats");
        } else {
          reject("Invalid Username / Password");
        }
      })
      .catch(function() {
        reject("Please try again later.");
      });
  });
};

User.prototype.register = function() {
  // Step : 1 : Validate User Data
  this.cleanUp();
  this.validate();
  //Step : 2: Only If there are no validation errors
  if (!this.errors.length) {
    //hash user password
    let salt = bcrypt.genSaltSync(10);
    this.data.password = bcrypt.hashSync(this.data.password, salt);
    usersCollection.insertOne(this.data);
  }
  // then save the user data into a database
};
module.exports = User;

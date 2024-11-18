const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let registeredUsername = "";
let username = "";
const users = new Map();

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    registeredUsername = input;
    console.log(`Welcome, ${username} to the chat`);

    socket.emit("registerPublicKey", {
      username,
      publicKey: publicKey.export({ type: "pkcs1", format: "pem" }),
    });
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        if ((match = message.match(/^!impersonate (\w+)$/))) {
          username = match[1];
          console.log(`Now impersonating as ${username}`);
        } else if (message.match(/^!exit$/)) {
          username = registeredUsername;
          console.log(`Now you are ${username}`);
        } else {
          try {
            const signature = crypto.sign("sha256", Buffer.from(message), privateKey);

            socket.emit("message", {
              username,
              message,
              signature: signature.toString("base64"),
            });
          } catch (error) {
            console.error("Error signing the message:", error.message);
          }
        }
      }
      rl.prompt();
    });
  });
});

socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username, publicKey } = data;
  users.set(username, publicKey);
  console.log(`${username} joined the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  if (!data || !data.message || !data.signature || !data.username) {
    console.log("Received malformed message from the server");
    rl.prompt();
    return;
  }

  const { username: senderUsername, message: senderMessage, signature } = data;

  if (users.has(senderUsername)) {
    const senderPublicKey = users.get(senderUsername);

    try {
      const isValid = crypto.verify(
        "sha256",
        Buffer.from(senderMessage),
        {
          key: senderPublicKey,
          format: "pem",
        },
        Buffer.from(signature, "base64")
      );

      if (isValid) {
        console.log(`${senderUsername}: ${senderMessage}`);
      } else {
        console.log(`${senderUsername}: ${senderMessage} [WARNING: this user is fake]`);
      }
    } catch (error) {
      console.error(`Error verifying message from ${senderUsername}:`, error.message);
    }
  } else {
    console.log(`${senderUsername}: ${senderMessage} [WARNING: public key not found]`);
  }
  rl.prompt();
});

socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});

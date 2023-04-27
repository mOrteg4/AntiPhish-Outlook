/*
 * Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
 * See LICENSE in the project root for license information.
 */

/* global document, Office */

Office.onReady((info) => {
  if (info.host === Office.HostType.Outlook) {
    document.getElementById("sideload-msg").style.display = "none";
    document.getElementById("app-body").style.display = "flex";
    document.getElementById("run").onclick = run;
  }
});

// Function to get email contents
async function getEmailContents() {
  return new Promise((resolve, reject) => {
    Office.context.mailbox.item.body.getAsync("text", {}, function (asyncResult) {
      if (asyncResult.status === Office.AsyncResultStatus.Failed) {
        reject(asyncResult.error);
      } else {
        resolve(asyncResult.value);
      }
    });
  });
}

// Function to send email contents to Flask server
async function sendEmailContentsToFlask(emailContents) {
  const flaskServerURL = "http://localhost:5000/receive_email";
  const response = await fetch(flaskServerURL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email_contents: emailContents }),
  });
  return response.json();
}

// Function to handle the whole process
async function processEmail() {
  try {
    const emailContents = await getEmailContents();
    const response = await sendEmailContentsToFlask(emailContents);
    console.log(response);
  } catch (error) {
    console.error("Error:", error);
  }
}

async function checkForResponse() {
  try {
    document.getElementById("status-message").innerText = "Python file has not loaded yet. Please Wait.";
    const response = await fetch('http://localhost:5000/');
    const text = await response.text();
    document.getElementById("status-message").innerText = text;
  } catch (error) {
    console.error("Error:", error);
    document.getElementById("status-message").innerText = "Python file has not loaded yet. Please Wait.";
    // Wait for 5 seconds before calling the function again
    await new Promise(resolve => setTimeout(resolve, 5000));
    checkForResponse();
  }
}


export async function run() {
  // Get a reference to the current message
  const item = Office.context.mailbox.item;

  // Write message property value to the task pane
  document.getElementById("item-subject").innerHTML = "<b>Subject:</b> <br/>" + item.subject;
  document.getElementById("item-sender").innerHTML = "<b>Sender:</b> " + item.sender.emailAddress;

  // Get the email body content
  item.body.getAsync("text", { asyncContext: null }, async function (result) {
    var body = result.value;

    // Combine subject and body
    var emailContent = item.subject + " " + body;
    processEmail()
    document.getElementById("status-message").innerText = "Checking...";
    checkForResponse()
  });
}

const toggleSwitch = document.querySelector('#toggle-switch');
toggleSwitch.addEventListener('change', switchTheme);
function switchTheme(event) {
  if (event.target.checked) {
  document.body.classList.add('dark-mode');
  } else {
  document.body.classList.remove('dark-mode');
  }
}

const isDarkMode = JSON.parse(localStorage.getItem('dark-mode'));
if (isDarkMode) {
toggleSwitch.checked = true;
document.body.classList.add('dark-mode');
}
toggleSwitch.addEventListener('change', function() {
localStorage.setItem('dark-mode', toggleSwitch.checked);
});

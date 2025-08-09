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
})

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

    document.getElementById("status-message").innerText = "Checking...";

    try {
      const response = await fetch("http://localhost:5000/check_email", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email_contents: emailContent }),
      });
      const responseText = await response.text();
      document.getElementById("status-message").innerText = responseText;
    } catch (error) {
      console.error("Error:", error);
      document.getElementById("status-message").innerText = "Error checking email. Please try again.";
    }
  });
}

const moonToggle = document.getElementById('moon-toggle');
const body = document.body;

moonToggle.addEventListener('click', function() {
  if (body.classList.contains('dark-mode')) {
    body.classList.remove('dark-mode');
    moonToggle.innerHTML = '☾';
  } else {
    body.classList.add('dark-mode');
    moonToggle.innerHTML = '☼';
  }
});
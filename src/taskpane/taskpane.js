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
    // applyOfficeTheme()
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

function detectDarkMode() {
  const darkModeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

  function setDarkModeClass() {
      if (darkModeMediaQuery.matches) {
          document.documentElement.classList.add('dark-mode');
      } else {
          document.documentElement.classList.remove('dark-mode');
      }
  }
  
  setDarkModeClass();

  darkModeMediaQuery.addEventListener('change', setDarkModeClass);
}

detectDarkMode();

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

// async function applyOfficeTheme() {
//   try {
//     // Get office theme colors.
//     const theme = await Office.context.officeTheme.getThemeAsync();
//     const isDarkTheme = theme.theme === "black";

//     // Set body background and text color based on the theme.
//     const bodyBackgroundColor = isDarkTheme ? theme.bodyBackgroundColor : "#FFFFFF";
//     const bodyForegroundColor = isDarkTheme ? theme.bodyForegroundColor : "#000000";
//     const textColor = isDarkTheme ? "#FFFFFF" : "#000000";

//     // Apply body background color and text color to CSS classes.
//     $('.ms-welcome__header').css('background-color', bodyBackgroundColor);
//     $('.body').css('background-color', bodyForegroundColor);
//     $('.ms-welcome__header').css('color', textColor);
//     $('.body').css('color', textColor);
//   } catch (error) {
//     console.error("Error applying Office theme:", error);
//   }
// }
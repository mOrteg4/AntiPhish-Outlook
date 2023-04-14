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

export async function run() {
  /**
   * Insert your Outlook code here
   */
  // Get a reference to the current message
  const item = Office.context.mailbox.item;

  // Write message property value to the task pane
  document.getElementById("item-subject").innerHTML = "<b>Subject:</b> <br/>" + item.subject;
}





function handleButtonAction(event) {
  // Get the item (email) being read
  var item = Office.context.mailbox.item;

  // Get the email subject
  var subject = item.subject;

  // Get the email body
  item.body.getAsync("text", { asyncContext: null }, function (result) {
    var body = result.value;
    // Process the email content and interact with your Python script as needed

    // ... Your logic here ...

    // Don't forget to call event.completed() when you're done processing
    event.completed();
  });
}
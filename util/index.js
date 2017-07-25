var jwt = require("jsonwebtoken");
var db = require("../db");
var config = require("../config");
var request = require("request");

var util = {
  login: user => {
    if (user) {
      if (!db.users.get(user)) {
        // save user in db
        db.users.set(user, { name: user });
      }
      return true;
    } else {
      return false;
    }
  },
  hasAccess: (user, document) =>
    document.owner == user || document.access.some(x => user == x),
  getPSPDFKitToken: document_id =>
    jwt.sign(
      {
        document_id: document_id,
        permissions: ["read-document", "edit-annotations", "download"]
      },
      config.pspdfkitJWTKey,
      {
        algorithm: "RS256",
        expiresIn: 10 * 365 * 24 * 60 * 60 // 10yrs
      }
    ),
  shareDocument: (user, document_id, users) => {
    if (util.hasAccess(user, db.docs.get(document_id))) {
      db.docs.update(document_id.toString(), document => {
        document.access = users;
        return document;
      });
      return true;
    }
    return false;
  },
  upload: function upload(file, user, callback) {
    request(
      {
        method: "POST",
        url: `${config.pspdfkitBaseUrl}/api/document`,
        headers: {
          Authorization: `Token token=${config.pspdfkitAuthToken}`,
          "Content-Type": "application/pdf"
        },
        body: file.buffer
      },
      (err, remoteResponse, remoteBody) => {
        if (err) {
          return callback(err);
        } else if (remoteResponse.statusCode !== 200) {
          return callback(remoteResponse);
        }

        var data = JSON.parse(remoteBody).data;

        var pspdfkitToken = jwt.sign(
          { document_id: data.document_id, permissions: ["cover-image"] },
          config.pspdfkitJWTKey,
          {
            algorithm: "RS256",
            expiresIn: 10 * 365 * 24 * 60 * 60 // 10 years
          }
        );
        var cover_url = `${config.pspdfkitBaseUrl}/documents/${data.document_id}/cover?width=200&jwt=${pspdfkitToken}`;

        var uploadData = {
          id: data.document_id,
          title: file.originalname,
          cover_url: cover_url,
          owner: user,
          access: []
        };

        db.docs.set(data.document_id, uploadData);

        callback(null, uploadData);
      }
    );
  },
  userDocuments: user => {
    let docs = [];

    db.docs.forEach((k, document) => {
      if (util.hasAccess(user, document)) {
        docs.push(document);
      }
    });

    return docs;
  }
};

module.exports = util;

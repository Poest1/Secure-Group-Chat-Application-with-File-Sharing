Client-Server Architecture:  connection-oriented communication model between clients and server.
Confidential Communication: secure communication where messages and files are encrypted.
Integrity Service:  communication service so that files and messages can be verified to be authentic.
Group Chat: Enable clients to join a group (there is only one group that includes all connected clients) and communicate with other group members by sending text messages.
File Sharing: Allow clients to upload files to the server and download files shared by other clients within the group, with a maximum file size limit of 50 MB.
When sending a file, the sender will provide the name and size of the file along with the actual file to the server.
The server will notify other clients of the broadcasted file, and the clients will accept or deny the file.
If a client accepts a file, the file will be sent.
Ensure that any message or file uploaded by a client is broadcast to all other connected clients within the group. 
All communication is synchronous, meaning only available clients will get the messages and the files. If the clients go down or new clients come, they will not get the messages. 
User Authentication: Not required.
User Interface:user-friendly interface for the clients to interact with the application, allowing them to send messages and upload/download files easily.

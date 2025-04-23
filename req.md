# ASSIGNMENT 1

## DEVELOP A NETWORK APPLICATION

## COURSE:^ COMPUTER^ NETWORKS,^ SEMESTER^ 1,^ 2024-^

#### OBJECTIVES

Build a **simple segment chat application** (Discord-like) with application protocols defined by
each group, using the TCP/IP protocol stack.

(^)

#### APPLICATION DESCRIPTION

## Application overview

#### ● Hybrid paradigm: This application uses both client-server paradigm and peer-to-peer

paradigm.
● The application performs the client-server during the initialization time to submit the
information of upcoming new peers.

#### ● The application leverages peer-to-peer to broadcast the content from one peer to all

other peers (as a live streaming session).
● The application supports client-server when the live streamer is offline which is in low
traffic conditions.

#### ● Hosts: there are two types of hosts in this system: a centralized server and several

normal PCs.

## System infrastructure in hybrid paradigm

```
Figure 1. Illustration of segment chat system.
```

#### ● A peer is an application instance running on a specific host. Three different instances of

the application running on a single host are described as 3 peers.

#### ● A centralized server has a tracker that keeps the tracking list of the peers that are

connected.

#### ● A peer who joins the system will submit its information to the centralized server and this

information is updated to the centralized server tracking list.

#### ● A peer can request the current list of systems.

● The detailed connection steps are:
○ 1. submit_info: new peer submit its host IP and its port
○ 2. add_list: tracker process on the centralized server add the new information
to the tracking list
○ 3. get_list: the centralized server response with the tracking list on peer
request
○ 4. peer_connect based on the obtained tracking list, the peer connects directly
to another peer.

## System components

### The components of the simple segment chat application system are listed below:

## Authentication

### Visitor mode : users can connect to the system to retrieve the channel content but they

### are forbidden to perform any content modification. Besides, the channel can set the

### permission to not allow visitor viewing operation.

#### o The detailed specifications of this mode are:

#### ▪ Visitors do not need to login (no authentication required)

#### ▪ Visitors need to give/declare a naming through an input text.

#### ▪ Visitors are granted view permission only.

#### ▪ Visitors are not allowed to edit/create content.

### Authenticated-user mode: these users are required to login to authenticate and mapping

### the access control list.

#### o The detailed specifications of this mode are:

#### ▪ Authenticated-users is mandated to login

#### ▪ Authenticated-users are granted all edit/create content permission.

```
o The user has different displayed status
```
#### ▪ Online mode: its online status are shown visible to all other

#### authenticated-users

#### ▪ Offline mode: it has no connection to the system.

#### ▪ Invisible mode: its status is displayed offline only, but it has connection to

#### the system and works normally as same as online mode.

### To shorten the text, we refer to the user as authenticated-user in the remainder of this

### document.


## Channel

### Channel is a single list of chatting messages. The users need to support the following

### channel operations:

```
o List the channels that the users joined.
o Each channel has a scrolled window that displays the message list.
o Each channel supports a UI input component (input textbox, submission button)
to allow users to create a new message and submit it.
o In the message list, we do not need to support edit/delete messages since it is
not the objective of the network course. The course outcome has zero proportion
of scoring on the convenience or beauty of the application.
o As the course outcome, it needs to send the data of the message to the
destination. And it might create a notification when another message is created.
o Channel can support a customization policy on access list control but since we
have much task to do and the main focus is the illustration of the course CO
outcome, in which it provide the data connection among computers, then access
control is an option only (no scoring proportion)
```
## Personal own server or Channel hosting

#### **NOTICE** In this application style, the term “server” is NOT used to describe the

#### physical machine where the services are deployed.

#### Server refers to the host that co-locates a set of channels (placed at the same

#### location). As usual, that set belongs to one owner user. Other channels the owner

#### users join are listed in the channel list not this channel hosting section. To clarify the

#### functionality, we call it Channel-hosting. Students are free to interchange between

#### the two terms, server as common sense application usage while channel hosting as

#### theoretical paradigm.

#### o Channels in channel hosting vs joined-only channels: the former set of channels

#### is owned by the current user and is stored on the peer that user is logging in.

#### These channels might have a copy on the centralized server but these copies are

#### mainly for backup purposes and are not primary storage repositories. The latter

#### set of channels is simply cached content to reduce the access time to the remote

#### peer. In accessing context, we use channels to represent both sets of channels,

#### but in storage context, we need to indicate the exact type of the concerned

#### channel set.

#### o Channel-hosting connection: when a user changes from offline to online, it needs

#### to synchronize between the content in local peer and the content on the

#### centralized server. During the online period, it keeps updating in both places

#### synchronously.

#### Remember that Discord was invented early for gaming streaming purposes where

#### it has a large user actively for a while during the live session.


#### The direct connection between channel-hosting and viewer user is used in the

#### peer-to-peer paradigm which supports a time sensitive data transfer and large

#### scale. The maintenance of a copy on the centralized server costs only one

#### connection and once transfer time. If all viewer users access the server it will

#### cause the bottleneck as a traditional problem in client-server paradigm. The one

#### copy on the centralized server is accessed when the live stream user is offline

#### and out of the live session where the traffic amount is small therefore the

#### centralized server is strong enough to handle it.

#### o The synchronization between channel-hosting and the centralized server is

#### illustrated as in the following scenarios:

#### We denote A and B are the data content (text/chat/message)
Below, I’ll expand the workflow of the segment chat application in greater detail, focusing on the synchronization and content-fetching mechanisms as outlined in the tables on pages 4 and 5 of the document. These tables describe the behavior of the system under various scenarios—Channel Hosting going offline/online, Livestream period, and Joined User going offline/online—across the key entities: Channel Hosting, Centralized Server, and Joined Users (X and Y). I’ll integrate the hybrid client-server and peer-to-peer paradigms, providing a step-by-step explanation of how the network operates in each case.
________________________________________
Workflow Overview
The workflow revolves around managing channel content (e.g., chat messages denoted as A and B) across the system, ensuring peers can fetch and synchronize data efficiently. The system prioritizes direct peer-to-peer communication when the channel host is online (e.g., during live streaming) and falls back to the centralized server when the host is offline. Each scenario illustrates how data is created, synced, and fetched, with the TCP/IP stack facilitating all communications.
________________________________________
1. Channel Hosting Goes Offline
Scenario: The peer hosting a channel (Channel Hosting) disconnects from the system, leaving Joined Users X and Y active.
Detailed Workflow:
1.	Initial State:
o	Channel Hosting has previously created content A and synced it to the Centralized Server.
o	Channel Hosting goes offline (e.g., closes the application or loses connection).
2.	Centralized Server:
o	Maintains a copy of content A, previously synced when Channel Hosting was online.
o	Becomes the primary source of content A while Channel Hosting is unavailable.
3.	Joined User X:
o	Detects that Channel Hosting is offline (e.g., via a failed connection attempt or a status update from the Centralized Server).
o	Connects to the Centralized Server using a client-server TCP connection.
o	Fetches content A from the Centralized Server.
o	Creates new content B locally (as an authenticated user with edit permissions).
o	Sends content B to the Centralized Server via a synchronization message, ensuring it’s stored there.
4.	Joined User Y:
o	Similarly detects Channel Hosting’s offline status.
o	Connects to the Centralized Server and fetches content A.
o	After User X creates content B and syncs it, User Y fetches content B from the Centralized Server.
5.	Channel Hosting (Offline):
o	If it creates new content A locally while offline (e.g., in a cached state), this content remains unsynced until it reconnects.
o	No communication occurs with other entities until it goes online.
6.	Network Operations:
o	Client-Server: Joined Users X and Y use TCP to connect to the Centralized Server, requesting content with a custom protocol (e.g., get_content).
o	Synchronization: User X’s new content B is uploaded to the Centralized Server (e.g., sync_content message).
o	Logging: Each fetch and sync operation is logged (e.g., “Fetched A from Centralized Server at [timestamp]”).
Outcome:
•	Content A is accessible via the Centralized Server, and new content B is stored there, ensuring availability despite the Channel Hosting’s absence.
________________________________________
2. Channel Hosting Goes Online
Scenario: The Channel Hosting peer reconnects to the system after being offline.
Detailed Workflow:
1.	Initial State:
o	Channel Hosting has content A created locally while offline (cached but not synced).
2.	Channel Hosting:
o	Establishes a TCP connection to the Centralized Server.
o	Syncs content A to the Centralized Server using a synchronization protocol (e.g., sync_content A).
o	Becomes the primary source for content distribution.
o	Creates new content A (if applicable) and immediately syncs it to the Centralized Server.
3.	Centralized Server:
o	Receives content A from Channel Hosting and updates its backup copy.
o	Syncs any new content (e.g., B created by Joined Users while Channel Hosting was offline) back to Channel Hosting.
4.	Joined User X:
o	Detects Channel Hosting is online (e.g., via an updated peer list from the Centralized Server).
o	Establishes a peer-to-peer TCP connection to Channel Hosting.
o	Fetches content A directly from Channel Hosting.
o	Creates new content B and sends it to Channel Hosting, which syncs it to the Centralized Server.
5.	Joined User Y:
o	Connects to Channel Hosting via peer-to-peer and fetches content A.
o	Fetches content B from Channel Hosting after User X creates it.
6.	Network Operations:
o	Client-Server: Channel Hosting syncs with the Centralized Server upon reconnection.
o	Peer-to-Peer: Joined Users X and Y fetch content directly from Channel Hosting, reducing server load.
o	Synchronization: Bidirectional sync ensures consistency between Channel Hosting and the Centralized Server.
o	Logging: Logs include “Synced A to Centralized Server” and “Fetched A from Channel Hosting”.
Outcome:
•	Channel Hosting resumes its role as the primary content source, with all entities synchronized.
________________________________________
3. Livestream Period
Scenario: Channel Hosting is actively streaming, creating content in real-time (high-traffic scenario).
Detailed Workflow:
1.	Channel Hosting:
o	Creates new content A (e.g., a live chat message).
o	Broadcasts content A to all Joined Users via peer-to-peer connections.
o	Syncs content A to the Centralized Server as a backup (one-time transfer).
2.	Centralized Server:
o	Receives and stores a copy of content A for redundancy.
o	Does not serve content during the livestream unless Channel Hosting goes offline.
3.	Joined User X:
o	Maintains a peer-to-peer connection with Channel Hosting.
o	Fetches content A directly from Channel Hosting in real-time.
o	Creates new content B and sends it to Channel Hosting.
4.	Joined User Y:
o	Fetches content A from Channel Hosting via peer-to-peer.
o	Fetches content B from Channel Hosting after User X creates it.
5.	Network Operations:
o	Peer-to-Peer: Primary mode for real-time content distribution, leveraging direct TCP connections between peers.
o	Client-Server: Centralized Server receives a single sync of content A, avoiding bottlenecks.
o	Notifications: Channel Hosting may notify Joined Users of new content (e.g., via a polling mechanism or direct message).
o	Logging: Logs “Fetched A from Channel Hosting” and “Synced A to Centralized Server”.
Outcome:
•	Peer-to-peer dominates, ensuring scalability and low latency during the livestream, with the Centralized Server as a passive backup.
________________________________________
4. Joined User Goes Online
Scenario: Joined User X reconnects after being offline, with Channel Hosting and User Y active.
Detailed Workflow:
1.	Initial State:
o	Channel Hosting has content A, synced to the Centralized Server.
o	Joined User X has content B created locally while offline.
2.	Joined User X:
o	Connects to the Centralized Server to register and get the peer list.
o	Checks Channel Hosting’s status:
	If online, connects peer-to-peer and fetches content A from Channel Hosting.
	If offline, fetches content A from the Centralized Server.
o	Syncs content B to Channel Hosting (if online) or the Centralized Server (if Channel Hosting is offline).
3.	Channel Hosting:
o	Receives content B from Joined User X (if online).
o	Syncs content B to the Centralized Server.
4.	Centralized Server:
o	Provides content A to Joined User X if Channel Hosting is offline.
o	Stores content B from Joined User X for backup.
5.	Joined User Y:
o	Fetches content B from Channel Hosting (if online) or the Centralized Server (if Channel Hosting is offline).
6.	Network Operations:
o	Client-Server: Used for initial registration and fallback content fetching.
o	Peer-to-Peer: Preferred when Channel Hosting is online.
o	Synchronization: Ensures content B is propagated across the system.
o	Logging: Logs “Fetched A from Channel Hosting” or “Synced B to Centralized Server”.
Outcome:
•	Joined User X reintegrates seamlessly, syncing offline content and fetching updates.
________________________________________
5. Joined User Goes Offline
Scenario: Joined User X disconnects, leaving Channel Hosting and User Y active.
Detailed Workflow:
1.	Joined User X:
o	Creates new content B locally before going offline (cached, not synced).
o	Loses connection to the system.
2.	Channel Hosting:
o	Continues operating normally, unaware of Joined User X’s offline status unless notified (e.g., via a timeout).
o	Does not receive content B until Joined User X reconnects.
3.	Centralized Server:
o	No immediate action; waits for Joined User X to sync content B upon reconnection.
4.	Joined User Y:
o	Continues fetching content from Channel Hosting (if online) or the Centralized Server (if Channel Hosting is offline).
o	Does not see content B until Joined User X reconnects and syncs it.
5.	Network Operations:
o	Peer-to-Peer: Unaffected between Channel Hosting and Joined User Y.
o	Client-Server: Centralized Server remains passive until Joined User X returns.
o	Logging: Logs Joined User X’s local action (e.g., “Created B locally at [timestamp]”) once it reconnects.
Outcome:
•	Content B remains local to Joined User X until it goes online, ensuring no data loss.
________________________________________
Key Network Mechanics
•	Protocols:
o	Tracker Protocol: Manages peer registration and list updates (client-server).
o	Peer-to-Peer Protocol: Handles direct content fetching and broadcasting.
o	Synchronization Protocol: Ensures content consistency across entities.
•	TCP/IP Usage:
o	Reliable, connection-oriented TCP ensures no data loss during transfers.
o	IP addresses and ports uniquely identify peers and the Centralized Server.
•	Hybrid Paradigm:
o	Client-server for initialization and backup.
o	Peer-to-peer for real-time, scalable content distribution.
________________________________________
Summary
This detailed workflow, driven by the tables on pages 4 and 5, showcases how the segment chat application balances scalability and reliability. When Channel Hosting is online, peer-to-peer connections dominate, especially during livestreams, while the Centralized Server steps in during offline scenarios. Joined Users adapt dynamically, syncing offline content upon reconnection, ensuring a robust and flexible network system. Each step is logged, providing transparency for evaluation. This hybrid design effectively meets the assignment’s objectives of illustrating both paradigms using the TCP/IP stack.

### To keep it simple, we do not declare all small details. It is reasonable to assume that a

### joined user who creates new content is already an authenticated user. Therefore, it has

### the permission to edit/create new content. Visitors are excluded in that case since they

### have view permissions only and have no right to create a new content.

## User access

#### o user fetch: user fetch content when it changes from offline to online.

#### o user notification: when a new content is created, it is notified to the user by

#### notification mechanism and fetches the new content to the user application

#### instance. Students are free to design such a beautiful notification mechanism,


#### but in the case we lack the idea, a simple mechanism of getting a user list from

#### the centralized server and polling to send a notification to each user in the list is

#### a nice start.

#### o A note of user list: on each peer, there may be more than one instance of this

#### application, each instance has a unique peer port as usual. A user can log in

#### multiple times on different application instances via multiple sessions, then items

#### in the user list are unique by the tuple of (peer IP and port, username, session

#### ID). The user list is a list of these tuples.

## System Log

### To track the initialization of the connection in multi-direction communication. You might

### write a log entry for each connection and data transfer. The log file, as usual, is an ASCII

### text file to keep it simple format.

## Extra credit:

### Seeding strategies : a simple download strategy is designed for a single livestreamer. But

### if you choose to apply something fancier (like multi peer seeding), you need to

### document it and provide supplemental materials.

### Large scalability examination : To support billions of messages, Discord has passed

### through various technology improvements (*). If you have some estimation and collect

### some measurements to reproduce the numerical that shows different scalability on

### these technologies, it is a plus.

#### o In 2017, Discord use MongoDB to support 100 million stored message

#### o By 2022, their Cassandra cluster had 177 nodes with trillions of messages, but

#### faced serious performance issues.

#### o They decided to migrate to ScyllaDB, a Cassandra-compatible database written in

#### C++ which promised better performance, faster repairs, and stronger workload

#### isolation.

### *https://discord.com/blog/how-discord-stores-trillions-of-messages

### System API You can support API ase ((BASE_URL))/users/{user_id}/channels/ or some

### basics to demo the capabilities of autorunning bot through programmable API. The

### definition of the API is freely available for your brainstorming. You need to document it

### and provide supplemental materials.

**Bot or automation support** : demo that you can create an autoresponder bot in the application.


## Q&A

### https://docs.google.com/spreadsheets/d/1rUlqmEX1mX3PwfKobLRqWlWNCm08w

## qcHmG6Qc0PcVXw/edit?usp=sharing

## Grading

### Tracker Protocol - 20% (the initialization phase) successfully parses the metainfo, sends a

### request to the tracker, obtains its response with the list of corresponding peers, and

### parses the list of peers into useful ’ip’ and ’port’ pairs.

### Client server paradigm - 20% data transfer when a peer need to connect to the tracker

### on the centralized server

### Peer to peer paradigm - 20% (the live stream phase) data transfer when a peer becomes

### a living streamer and supports peer connections and data transfer among peers.

### Readme - 10% document your design, as well as any errors or features.

### Synchronization between Channel-hosting and centralized server feature - 10%

**Connection logging** - it needs to log the connected host (either centralized host or channel
hosting) for each message or notification. Simple log file is fine, we can clear and log a new file
when the log is longer than 10.000 records. But this log is used to evaluate where your data are

### synchronized from. 10%

#### Advanced feature - 10%

#### WORKING PLAN

● Work in a team.
● Each group has 2-3 or up to 4 members.
Phase 1 (First 2 weeks):
● Define specific functions of the file-sharing application
● Define the communication protocols used for each function
Phase 2 (Next 2 weeks)
**●** Implement and refine the application according to the functions and protocols defined in
Phase 1

#### RESULTS

Phase 1 (softcopy):
**●** Submit the report file of the first phase to BKeL in the predefined section as announced
on BKeL.
**●** File format (pdf): **ASS1_P1_<<Group_Name>>.pdf**
This report includes:
**●** Define and describe the functions of the application


**●** Define the protocols used for each function
Phase 2 (hard and softcopy):
**●** Submit the report file of the assignment to BKeL
**●** File format (.rar): ASS1_ **<<Group_name>>** .rar
This report includes:
● Phase 1 content
● Describe each specific function of the application
● Detailed application design (architecture, class diagrams, main classes ...)
● Validation (sanity test) and evaluation of actual result (performance)
● Extension functions of the system in addition to the requirements specified in section 2
● Participants’ roles and responsibilities
● Manual document
● Source code (softcopy)
● Application file (softcopy) compiled from source code

#### E

#### EVALUATION

_Assignment 1 is worth 15% of the course grade._

#### DEADLINE FOR SUBMISSION

_3-4 weeks from the assignment announcement depends on the Lab teacher._

(^)



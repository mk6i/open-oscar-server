# Configuring File Transfer Over The Internet

## Context

In the OSCAR protocol, **Rendezvous** is a mechanism that lets two AIM clients exchange the necessary information to
establish a direct, peer-to-peer connection—typically used for file transfers.

Back in the early 2000s, most computers were assigned a **public IP address** directly from their ISP. As a result, when
one AIM client sent its IP address to another, that address was routable on the public Internet. Today, almost everyone
is behind a router performing Network Address Translation (NAT). Consequently, the sender’s machine usually only has a
**private IP address** (e.g., `192.168.x.x`), which cannot be reached directly over the Internet.

To work around this limitation, **Open OSCAR Server** can substitute your client’s private IP address with the server’s
view of your **public IP address**. However, you still need to configure **port forwarding** on your router to ensure
that incoming Rendezvous connections (for file transfers) are routed to the correct machine.

## Send File Setup

This guide explains how to configure your Windows AIM client to send files over the Internet using the **Send File**
feature. If you only need to **receive** a file, no additional setup is required.

### Caveats

- **Same LAN Scenario**  
  If both Open OSCAR Server and your AIM client are on the same local network (LAN), you do **not** need these steps.

- **Mixed LAN and Internet**  
  If the sending client and the server are on the same LAN while the receiver is on the Internet, this guide may not
  work as intended.

- **Security Notice**  
  Rendezvous makes your IP address visible to the recipient. Opening a port on your home network allows inbound Internet
  traffic to reach your computer on that port. Use careful judgment and consider the security implications before
  proceeding.

### 1. Configure AIM Port

1. Open the **AIM Preferences** window.
2. Select **File Transfer** from the sidebar or menu.
3. In the **Port number to use** field, enter a high port number such as `4000`.

### 2. Set Up Router Port Forwarding

1. Log in to your router’s admin interface.
2. Create a new **port forwarding** rule:
    - Forward **TCP** port `4000` (or the port you chose)
    - Send that traffic to the **local IP address** of the computer running AIM
3. Save or apply the changes.

### 3. Send a File

Once everything is set up:

1. Start an IM with a friend.
2. Go to **File** > **Send File...** (or use the appropriate menu option in your AIM client).
3. Choose the file you want to send.
4. Your friend should now receive a prompt to accept or decline the file.

If the receiver is on the Internet and your port forwarding is correct, the direct file transfer should succeed.

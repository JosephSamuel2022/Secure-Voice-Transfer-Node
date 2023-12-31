const express = require("express");
const app = express();
const http = require("http");
const cors = require("cors");
const { Server } = require("socket.io");
app.use(cors());

const server = http.createServer(app);

const io = new Server(server, {
	cors: {
		origin: "https://secure-voice-transfer.vercel.app",
		methods: ["GET", "POST"],
	},
});

io.on("connection", (socket) => {
	console.log(`User Connected: ${socket.id}`);

	socket.on("send_number", (data) => {
		// Emit the received number to all connected clients except the sender
		io.emit("receive_number", {
			number: data.number,
			senderId: socket.id, // Include the sender's ID
		});
	});

	socket.on("disconnect", () => {
		console.log("User Disconnected", socket.id);
	});
});

server.listen(3001, () => {
	console.log("SERVER RUNNING");
});

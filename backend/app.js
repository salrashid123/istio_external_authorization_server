const express = require('express');

const app = express();
var rp = require('request-promise');
const dns = require('dns');
const morgan = require('morgan');

const port = 8080;

app.use(
  morgan('combined')
);

var winston = require('winston');
var logger = winston.createLogger({
  transports: [
    new (winston.transports.Console)({ level: 'info' })
  ]
 });

app.get('/', (request, response) => {
  logger.info('Called /');
  response.send('Hello from Express!');
})

app.get('/_ah/health', (request, response) => {
  response.send('ok');
})

app.get('/varz', (request, response) => {
  response.send(process.env);
})

app.get('/version', (request, response) => {
  response.send(process.env.VER);
})

app.get('/backend', (request, response) => {
  var auth_header = request.headers['authorization']; 
  logger.info("Got Authorization Header: [" + auth_header + "]");
  response.send('pod: [' + process.env.MY_POD_NAME + ']    node: [' + process.env.MY_NODE_NAME + ']');
})

app.get('/headerz', (request, response) => {
  logger.info('/headerz');
  response.send(request.headers);
})

const server = app.listen(port, () => logger.info('Running…'));


setInterval(() => server.getConnections(
  (err, connections) => console.log(`${connections} connections currently open`)
), 60000);

process.on('SIGTERM', shutDown);
process.on('SIGINT', shutDown);

let connections = [];

server.on('connection', connection => {
  connections.push(connection);
  connection.on('close', () => connections = connections.filter(curr => curr !== connection));
});

function shutDown() {
  console.log('Received kill signal, shutting down gracefully');
  server.close(() => {
      logger.info('Closed out remaining connections');
      process.exit(0);
  });

  setTimeout(() => {
      logger.error('Could not close connections in time, forcefully shutting down');
      process.exit(1);
  }, 10000);

  connections.forEach(curr => curr.end());
  setTimeout(() => connections.forEach(curr => curr.destroy()), 5000);
}

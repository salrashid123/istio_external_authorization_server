const express = require('express');

const app = express();
var rp = require('request-promise');
const dns = require('dns');
const morgan = require('morgan');

const port = 8080;

const FORWARD_AUTH_HEADER = process.env.FORWARD_AUTH_HEADER || 'false';
const BACKEND_NAMESPACE = process.env.BACKEND_NAMESPACE || 'default';

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


  dns.resolveSrv("_http._tcp.be."+ BACKEND_NAMESPACE + ".svc.cluster.local",  function onLookup(err, addresses, family) {

      if (err) {
        response.send(err);
      } else if (addresses.length >= 1) {
        logger.info('addresses: ' + JSON.stringify(addresses));
        var host = addresses[0].name;
        var port = addresses[0].port;
        logger.info(host + " --> " + port);

        var resp_promises = []
        var urls = [
                    'http://' + host + ':' + port + '/backend',
                    'http://' + host + ':' + port + '/headerz',
        ]

        out_headers = {};
        if (FORWARD_AUTH_HEADER == 'true') {
          var auth_header = request.headers['authorization']; 
          logger.info("Got Authorization Header: [" + auth_header + "]");
          out_headers = {
              'authorization':  auth_header,
          };
        }

        urls.forEach(element => {
          resp_promises.push( getURL(element,out_headers) )
        });

        Promise.all(resp_promises).then(function(value) {
          response.send(value);
        }, function(value) {
          response.send(value);
        });

      } else{
        response.send('No Backend Services found');
      }
  });
})

function getURL(u, headers) {
  logger.info("Sending outbound Headers  --> " + JSON.stringify(headers, null, 2));
  var options = {
    method: 'GET',
    uri: u,
    resolveWithFullResponse: true,
    simple: false,
    headers: headers
  };
  return rp(options)
    .then(function (resp) {
        return Promise.resolve(
          { 'url' : u, 'body': resp.body, 'statusCode': resp.statusCode }
        );
    })
    .catch(function (err) {
        return Promise.resolve({ 'url' : u, 'statusCode': err } );
    });
}

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

"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.main = main;

require("core-js");

var _jsonrpc = require("./jsonrpc");

var _utils = require("./utils");

const server = (0, _jsonrpc.createJsonRpcServer)();

async function main(body) {
  const result = await server.receive(body);

  if (result) {
    return result;
  } else {
    return new _utils.Response(204, "");
  }
} // vim: sw=2:ts=2:expandtab:fdm=syntax
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9hcHAudHMiXSwibmFtZXMiOlsic2VydmVyIiwibWFpbiIsImJvZHkiLCJyZXN1bHQiLCJyZWNlaXZlIiwiUmVzcG9uc2UiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTs7QUFDQTs7QUFDQTs7QUFFQSxNQUFNQSxNQUFNLEdBQUcsbUNBQWY7O0FBRU8sZUFBZUMsSUFBZixDQUFvQkMsSUFBcEIsRUFBMEI7QUFDL0IsUUFBTUMsTUFBTSxHQUFHLE1BQU1ILE1BQU0sQ0FBQ0ksT0FBUCxDQUFlRixJQUFmLENBQXJCOztBQUNBLE1BQUlDLE1BQUosRUFBWTtBQUNWLFdBQU9BLE1BQVA7QUFDRCxHQUZELE1BRU87QUFDTCxXQUFPLElBQUlFLGVBQUosQ0FBYSxHQUFiLEVBQWtCLEVBQWxCLENBQVA7QUFDRDtBQUNGLEMsQ0FFRCIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCBcImNvcmUtanNcIjtcbmltcG9ydCB7IGNyZWF0ZUpzb25ScGNTZXJ2ZXIgfSBmcm9tIFwiLi9qc29ucnBjXCI7XG5pbXBvcnQgeyBSZXNwb25zZSB9IGZyb20gXCIuL3V0aWxzXCI7XG5cbmNvbnN0IHNlcnZlciA9IGNyZWF0ZUpzb25ScGNTZXJ2ZXIoKTtcblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIG1haW4oYm9keSkge1xuICBjb25zdCByZXN1bHQgPSBhd2FpdCBzZXJ2ZXIucmVjZWl2ZShib2R5KTtcbiAgaWYgKHJlc3VsdCkge1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH0gZWxzZSB7XG4gICAgcmV0dXJuIG5ldyBSZXNwb25zZSgyMDQsIFwiXCIpO1xuICB9XG59XG5cbi8vIHZpbTogc3c9Mjp0cz0yOmV4cGFuZHRhYjpmZG09c3ludGF4XG4iXX0=
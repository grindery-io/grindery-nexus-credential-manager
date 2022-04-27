"use strict";

require("dotenv/config");

var _bodyParser = _interopRequireDefault(require("body-parser"));

var _express = _interopRequireDefault(require("express"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

const app = (0, _express.default)();
app.use(_bodyParser.default.json()); // eslint-disable-next-line @typescript-eslint/no-var-requires

app.post("/", require("./index").http);
const port = parseInt(process.env.PORT || "", 10) || 3000;
console.log(`Listening on port ${port}`);
app.listen(port);
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9zZXJ2ZXIudHMiXSwibmFtZXMiOlsiYXBwIiwidXNlIiwiYm9keVBhcnNlciIsImpzb24iLCJwb3N0IiwicmVxdWlyZSIsImh0dHAiLCJwb3J0IiwicGFyc2VJbnQiLCJwcm9jZXNzIiwiZW52IiwiUE9SVCIsImNvbnNvbGUiLCJsb2ciLCJsaXN0ZW4iXSwibWFwcGluZ3MiOiI7O0FBQUE7O0FBQ0E7O0FBQ0E7Ozs7QUFFQSxNQUFNQSxHQUFHLEdBQUcsdUJBQVo7QUFDQUEsR0FBRyxDQUFDQyxHQUFKLENBQVFDLG9CQUFXQyxJQUFYLEVBQVIsRSxDQUVBOztBQUNBSCxHQUFHLENBQUNJLElBQUosQ0FBUyxHQUFULEVBQWNDLE9BQU8sQ0FBQyxTQUFELENBQVAsQ0FBbUJDLElBQWpDO0FBRUEsTUFBTUMsSUFBSSxHQUFHQyxRQUFRLENBQUNDLE9BQU8sQ0FBQ0MsR0FBUixDQUFZQyxJQUFaLElBQW9CLEVBQXJCLEVBQXlCLEVBQXpCLENBQVIsSUFBd0MsSUFBckQ7QUFFQUMsT0FBTyxDQUFDQyxHQUFSLENBQWEscUJBQW9CTixJQUFLLEVBQXRDO0FBQ0FQLEdBQUcsQ0FBQ2MsTUFBSixDQUFXUCxJQUFYIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IFwiZG90ZW52L2NvbmZpZ1wiO1xuaW1wb3J0IGJvZHlQYXJzZXIgZnJvbSBcImJvZHktcGFyc2VyXCI7XG5pbXBvcnQgZXhwcmVzcyBmcm9tIFwiZXhwcmVzc1wiO1xuXG5jb25zdCBhcHAgPSBleHByZXNzKCk7XG5hcHAudXNlKGJvZHlQYXJzZXIuanNvbigpKTtcblxuLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIEB0eXBlc2NyaXB0LWVzbGludC9uby12YXItcmVxdWlyZXNcbmFwcC5wb3N0KFwiL1wiLCByZXF1aXJlKFwiLi9pbmRleFwiKS5odHRwKTtcblxuY29uc3QgcG9ydCA9IHBhcnNlSW50KHByb2Nlc3MuZW52LlBPUlQgfHwgXCJcIiwgMTApIHx8IDMwMDA7XG5cbmNvbnNvbGUubG9nKGBMaXN0ZW5pbmcgb24gcG9ydCAke3BvcnR9YCk7XG5hcHAubGlzdGVuKHBvcnQpO1xuIl19
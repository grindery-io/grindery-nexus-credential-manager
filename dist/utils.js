"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.Response = void 0;

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

class Response {
  constructor(code, resp) {
    _defineProperty(this, "_code", void 0);

    _defineProperty(this, "_resp", void 0);

    this._code = code;
    this._resp = resp;
  }

  sendResponse(res) {
    if (this._code === 204) {
      res.status(204).send();
    }

    return res.status(this._code).json(this._resp);
  }

} // vim: sw=2:ts=2:expandtab:fdm=syntax


exports.Response = Response;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy91dGlscy50cyJdLCJuYW1lcyI6WyJSZXNwb25zZSIsImNvbnN0cnVjdG9yIiwiY29kZSIsInJlc3AiLCJfY29kZSIsIl9yZXNwIiwic2VuZFJlc3BvbnNlIiwicmVzIiwic3RhdHVzIiwic2VuZCIsImpzb24iXSwibWFwcGluZ3MiOiI7Ozs7Ozs7OztBQUVPLE1BQU1BLFFBQU4sQ0FBa0I7QUFHdkJDLEVBQUFBLFdBQVcsQ0FBQ0MsSUFBRCxFQUFlQyxJQUFmLEVBQXdCO0FBQUE7O0FBQUE7O0FBQ2pDLFNBQUtDLEtBQUwsR0FBYUYsSUFBYjtBQUNBLFNBQUtHLEtBQUwsR0FBYUYsSUFBYjtBQUNEOztBQUNERyxFQUFBQSxZQUFZLENBQUNDLEdBQUQsRUFBd0I7QUFDbEMsUUFBSSxLQUFLSCxLQUFMLEtBQWUsR0FBbkIsRUFBd0I7QUFDdEJHLE1BQUFBLEdBQUcsQ0FBQ0MsTUFBSixDQUFXLEdBQVgsRUFBZ0JDLElBQWhCO0FBQ0Q7O0FBQ0QsV0FBT0YsR0FBRyxDQUFDQyxNQUFKLENBQVcsS0FBS0osS0FBaEIsRUFBdUJNLElBQXZCLENBQTRCLEtBQUtMLEtBQWpDLENBQVA7QUFDRDs7QUFac0IsQyxDQWN6QiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCBleHByZXNzIGZyb20gXCJleHByZXNzXCI7XG5cbmV4cG9ydCBjbGFzcyBSZXNwb25zZTxUPiB7XG4gIF9jb2RlOiBudW1iZXI7XG4gIF9yZXNwOiBUO1xuICBjb25zdHJ1Y3Rvcihjb2RlOiBudW1iZXIsIHJlc3A6IFQpIHtcbiAgICB0aGlzLl9jb2RlID0gY29kZTtcbiAgICB0aGlzLl9yZXNwID0gcmVzcDtcbiAgfVxuICBzZW5kUmVzcG9uc2UocmVzOiBleHByZXNzLlJlc3BvbnNlKSB7XG4gICAgaWYgKHRoaXMuX2NvZGUgPT09IDIwNCkge1xuICAgICAgcmVzLnN0YXR1cygyMDQpLnNlbmQoKTtcbiAgICB9XG4gICAgcmV0dXJuIHJlcy5zdGF0dXModGhpcy5fY29kZSkuanNvbih0aGlzLl9yZXNwKTtcbiAgfVxufVxuLy8gdmltOiBzdz0yOnRzPTI6ZXhwYW5kdGFiOmZkbT1zeW50YXhcbiJdfQ==
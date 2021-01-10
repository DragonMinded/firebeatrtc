/* Do not edit, autogenerated by pscript */

var _pyfunc_divmod = function (x, y) { // nargs: 2
    var m = x % y; return [(x-m)/y, m];
};
var _pyfunc_enumerate = function (iter) { // nargs: 1
    var i, res=[];
    if ((typeof iter==="object") && (!Array.isArray(iter))) {iter = Object.keys(iter);}
    for (i=0; i<iter.length; i++) {res.push([i, iter[i]]);}
    return res;
};
var _pyfunc_format = function (v, fmt) {  // nargs: 2
    fmt = fmt.toLowerCase();
    var s = String(v);
    if (fmt.indexOf('!r') >= 0) {
        try { s = JSON.stringify(v); } catch (e) { s = undefined; }
        if (typeof s === 'undefined') { s = v._IS_COMPONENT ? v.id : String(v); }
    }
    var fmt_type = '';
    if (fmt.slice(-1) == 'i' || fmt.slice(-1) == 'f' ||
        fmt.slice(-1) == 'e' || fmt.slice(-1) == 'g') {
            fmt_type = fmt[fmt.length-1]; fmt = fmt.slice(0, fmt.length-1);
    }
    var i0 = fmt.indexOf(':');
    var i1 = fmt.indexOf('.');
    var spec1 = '', spec2 = '';  // before and after dot
    if (i0 >= 0) {
        if (i1 > i0) { spec1 = fmt.slice(i0+1, i1); spec2 = fmt.slice(i1+1); }
        else { spec1 = fmt.slice(i0+1); }
    }
    // Format numbers
    if (fmt_type == '') {
    } else if (fmt_type == 'i') { // integer formatting, for %i
        s = parseInt(v).toFixed(0);
    } else if (fmt_type == 'f') {  // float formatting
        v = parseFloat(v);
        var decimals = spec2 ? Number(spec2) : 6;
        s = v.toFixed(decimals);
    } else if (fmt_type == 'e') {  // exp formatting
        v = parseFloat(v);
        var precision = (spec2 ? Number(spec2) : 6) || 1;
        s = v.toExponential(precision);
    } else if (fmt_type == 'g') {  // "general" formatting
        v = parseFloat(v);
        var precision = (spec2 ? Number(spec2) : 6) || 1;
        // Exp or decimal?
        s = v.toExponential(precision-1);
        var s1 = s.slice(0, s.indexOf('e')), s2 = s.slice(s.indexOf('e'));
        if (s2.length == 3) { s2 = 'e' + s2[1] + '0' + s2[2]; }
        var exp = Number(s2.slice(1));
        if (exp >= -4 && exp < precision) { s1=v.toPrecision(precision); s2=''; }
        // Skip trailing zeros and dot
        var j = s1.length-1;
        while (j>0 && s1[j] == '0') { j-=1; }
        s1 = s1.slice(0, j+1);
        if (s1.slice(-1) == '.') { s1 = s1.slice(0, s1.length-1); }
        s = s1 + s2;
    }
    // prefix/padding
    var prefix = '';
    if (spec1) {
        if (spec1[0] == '+' && v > 0) { prefix = '+'; spec1 = spec1.slice(1); }
        else if (spec1[0] == ' ' && v > 0) { prefix = ' '; spec1 = spec1.slice(1); }
    }
    if (spec1 && spec1[0] == '0') {
        var padding = Number(spec1.slice(1)) - (s.length + prefix.length);
        s = '0'.repeat(Math.max(0, padding)) + s;
    }
    return prefix + s;
};
var _pyfunc_int = function (x, base) { // nargs: 1 2
    if(base !== undefined) return parseInt(x, base);
    return x<0 ? Math.ceil(x): Math.floor(x);
};
var _pyfunc_op_add = function (a, b) { // nargs: 2
    if (Array.isArray(a) && Array.isArray(b)) {
        return a.concat(b);
    } return a + b;
};
var _pyfunc_op_equals = function op_equals (a, b) { // nargs: 2
    var a_type = typeof a;
    // If a (or b actually) is of type string, number or boolean, we don't need
    // to do all the other type checking below.
    if (a_type === "string" || a_type === "boolean" || a_type === "number") {
        return a == b;
    }

    if (a == null || b == null) {
    } else if (Array.isArray(a) && Array.isArray(b)) {
        var i = 0, iseq = a.length == b.length;
        while (iseq && i < a.length) {iseq = op_equals(a[i], b[i]); i+=1;}
        return iseq;
    } else if (a.constructor === Object && b.constructor === Object) {
        var akeys = Object.keys(a), bkeys = Object.keys(b);
        akeys.sort(); bkeys.sort();
        var i=0, k, iseq = op_equals(akeys, bkeys);
        while (iseq && i < akeys.length)
            {k=akeys[i]; iseq = op_equals(a[k], b[k]); i+=1;}
        return iseq;
    } return a == b;
};
var _pyfunc_op_error = function (etype, msg) { // nargs: 2
    var e = new Error(etype + ': ' + msg);
    e.name = etype
    return e;
};
var _pyfunc_op_instantiate = function (ob, args) { // nargs: 2
    if ((typeof ob === "undefined") ||
            (typeof window !== "undefined" && window === ob) ||
            (typeof global !== "undefined" && global === ob))
            {throw "Class constructor is called as a function.";}
    for (var name in ob) {
        if (Object[name] === undefined &&
            typeof ob[name] === 'function' && !ob[name].nobind) {
            ob[name] = ob[name].bind(ob);
            ob[name].__name__ = name;
        }
    }
    if (ob.__init__) {
        ob.__init__.apply(ob, args);
    }
};
var _pyfunc_op_mult = function (a, b) { // nargs: 2
    if ((typeof a === 'number') + (typeof b === 'number') === 1) {
        if (a.constructor === String) return _pymeth_repeat.call(a, b);
        if (b.constructor === String) return _pymeth_repeat.call(b, a);
        if (Array.isArray(b)) {var t=a; a=b; b=t;}
        if (Array.isArray(a)) {
            var res = []; for (var i=0; i<b; i++) res = res.concat(a);
            return res;
        }
    } return a * b;
};
var _pyfunc_range = function (start, end, step) {
    var i, res = [];
    var val = start;
    var n = (end - start) / step;
    for (i=0; i<n; i++) {
        res.push(val);
        val += step;
    }
    return res;
};
var _pyfunc_str = String;
var _pyfunc_sum = function (x) {  // nargs: 1
    return x.reduce(function(a, b) {return a + b;});
};
var _pyfunc_truthy = function (v) {
    if (v === null || typeof v !== "object") {return v;}
    else if (v.length !== undefined) {return v.length ? v : false;}
    else if (v.byteLength !== undefined) {return v.byteLength ? v : false;}
    else if (v.constructor !== Object) {return true;}
    else {return Object.getOwnPropertyNames(v).length ? v : false;}
};
var _pymeth_append = function (x) { // nargs: 1
    if (!Array.isArray(this)) return this.append.apply(this, arguments);
    this.push(x);
};
var _pymeth_format = function () {
    if (this.constructor !== String) return this.format.apply(this, arguments);
    var parts = [], i = 0, i1, i2;
    var itemnr = -1;
    while (i < this.length) {
        // find opening
        i1 = this.indexOf('{', i);
        if (i1 < 0 || i1 == this.length-1) { break; }
        if (this[i1+1] == '{') {parts.push(this.slice(i, i1+1)); i = i1 + 2; continue;}
        // find closing
        i2 = this.indexOf('}', i1);
        if (i2 < 0) { break; }
        // parse
        itemnr += 1;
        var fmt = this.slice(i1+1, i2);
        var index = fmt.split(':')[0].split('!')[0];
        index = index? Number(index) : itemnr
        var s = _pyfunc_format(arguments[index], fmt);
        parts.push(this.slice(i, i1), s);
        i = i2 + 1;
    }
    parts.push(this.slice(i));
    return parts.join('');
};
var _pymeth_index = function (x, start, stop) { // nargs: 1 2 3
    start = (start === undefined) ? 0 : start;
    stop = (stop === undefined) ? this.length : stop;
    start = Math.max(0, ((start < 0) ? this.length + start : start));
    stop = Math.min(this.length, ((stop < 0) ? this.length + stop : stop));
    if (Array.isArray(this)) {
        for (var i=start; i<stop; i++) {
            if (_pyfunc_op_equals(this[i], x)) {return i;} // indexOf cant
        }
    } else if (this.constructor === String) {
        var i = this.slice(start, stop).indexOf(x);
        if (i >= 0) return i + start;
    } else return this.index.apply(this, arguments);
    var e = Error(x); e.name='ValueError'; throw e;
};
var _pymeth_join = function (x) { // nargs: 1
    if (this.constructor !== String) return this.join.apply(this, arguments);
    return x.join(this);  // call join on the list instead of the string.
};
var _pymeth_lower = function () { // nargs: 0
    if (this.constructor !== String) return this.lower.apply(this, arguments);
    return this.toLowerCase();
};
var _pymeth_repeat = function(count) { // nargs: 0
    if (this.repeat) return this.repeat(count);
    if (count < 1) return '';
    var result = '', pattern = this.valueOf();
    while (count > 1) {
        if (count & 1) result += pattern;
        count >>= 1, pattern += pattern;
    }
    return result + pattern;
};
var _pymeth_replace = function (s1, s2, count) {  // nargs: 2 3
    if (this.constructor !== String) return this.replace.apply(this, arguments);
    var i = 0, i2, parts = [];
    count = (count === undefined) ? 1e20 : count;
    while (count > 0) {
        i2 = this.indexOf(s1, i);
        if (i2 >= 0) {
            parts.push(this.slice(i, i2));
            parts.push(s2);
            i = i2 + s1.length;
            count -= 1;
        } else break;
    }
    parts.push(this.slice(i));
    return parts.join('');
};
var _pymeth_upper = function () { // nargs: 0
    if (this.constructor !== String) return this.upper.apply(this, arguments);
    return this.toUpperCase();
};
var BitArrayBuffer, KonamiRand, base36decode, base36encode, decode_firebeat_recovery_password, encode_firebeat_recovery_password, verify_date;
BitArrayBuffer = function () {
    _pyfunc_op_instantiate(this, arguments);
}
BitArrayBuffer.prototype._base_class = Object;
BitArrayBuffer.prototype.__name__ = "BitArrayBuffer";

BitArrayBuffer.prototype.__init__ = function (length) {
    this.buffer = _pyfunc_op_mult([0], length);
    return null;
};

BitArrayBuffer.prototype.xor = function (buffer2) {
    var buffer1_len, buffer2_len, i, new_buffer, output_buffer_len;
    buffer1_len = this.buffer.length;
    buffer2_len = buffer2.buffer.length;
    output_buffer_len = Math.min(buffer1_len, buffer2_len);
    new_buffer = _pyfunc_op_mult([0], output_buffer_len);
    for (i = 0; i < output_buffer_len; i += 1) {
        new_buffer[i] = this.buffer[i] ^ buffer2.buffer[i];
    }
    this.buffer = new_buffer;
    return null;
};

BitArrayBuffer.prototype.read = function (offset, bits) {
    var stub1_, stub1_i, stub1_i0, stub1_iter0, x;
    stub1_ = [];stub1_iter0 = _pyfunc_range(0, bits, 1);if ((typeof stub1_iter0 === "object") && (!Array.isArray(stub1_iter0))) {stub1_iter0 = Object.keys(stub1_iter0);}for (stub1_i0=0; stub1_i0<stub1_iter0.length; stub1_i0++) {stub1_i = stub1_iter0[stub1_i0];if (!((!_pyfunc_op_equals(this.buffer[_pyfunc_op_add(offset, stub1_i)], 0)))) {continue;}{stub1_.push(1 << stub1_i);}}
    x = stub1_;
    return (_pyfunc_truthy(x))? (_pyfunc_sum(x)) : (0);
};

BitArrayBuffer.prototype.write = function (offset, bits, to_write) {
    var i;
    for (i = 0; i < bits; i += 1) {
        this.buffer[_pyfunc_op_add(offset, i)] = ((!_pyfunc_op_equals((to_write & (1 << i)), 0)))? (1) : (0);
    }
    return null;
};


KonamiRand = function () {
    _pyfunc_op_instantiate(this, arguments);
}
KonamiRand.prototype._base_class = Object;
KonamiRand.prototype.__name__ = "KonamiRand";

KonamiRand.prototype.__init__ = function () {
    this.buffer_len = 55;
    this.buffer = _pyfunc_op_mult([0], (this.buffer_len + 2));
    return null;
};

KonamiRand.prototype.get_safe_val = function (val) {
    return (_pyfunc_op_add(val, (((val < 0))? (1000000000) : (0)))) & 4294967295;
};

KonamiRand.prototype.scramble = function () {
    var _inner_scramble;
    _inner_scramble = (function flx__inner_scramble (start, end, offset1, offset2) {
        var i, val;
        for (i = start; i < end; i += 1) {
            val = this.get_safe_val(this.buffer[_pyfunc_op_add(offset1, i)] - this.buffer[_pyfunc_op_add(offset2, i)]);
            this.buffer[_pyfunc_op_add(offset1, i)] = val;
        }
        return null;
    }).bind(this);

    _inner_scramble(1, 25, 0, 31);
    _inner_scramble(25, 56, 0, -24);
    return null;
};

KonamiRand.prototype.seed = function (inval) {
    var i, offset, val;
    this.buffer[this.buffer.length -2] = inval & 4294967295;
    val = 1;
    for (i = 1; i < 55; i += 1) {
        offset = _pyfunc_op_mult(i, 21) % 55;
        this.buffer[offset] = val;
        val = this.get_safe_val(inval - val);
        inval = this.buffer[offset];
    }
    this.scramble();
    this.scramble();
    this.scramble();
    this.buffer[this.buffer.length -1] = this.buffer_len;
    return null;
};

KonamiRand.prototype.next = function () {
    this.buffer[this.buffer.length -1] += 1;
    if ((this.buffer[this.buffer.length -1] > this.buffer_len)) {
        this.scramble();
        this.buffer[this.buffer.length -1] = 1;
    }
    return this.buffer[this.buffer[this.buffer.length -1]];
};


base36encode = function flx_base36encode (val, length, alphabet) {
    var _, i, output, stub2_;
    alphabet = (alphabet === undefined) ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789": alphabet;
    output = "";
    for (_ = 0; _ < length; _ += 1) {
        stub2_ = _pyfunc_divmod(val, 36);
        val = stub2_[0];i = stub2_[1];
        output = _pyfunc_op_add(output, alphabet[i]);
    }
    return output;
};

base36decode = function flx_base36decode (val, alphabet) {
    var c, i, output, stub3_seq, stub4_itr, stub5_tgt;
    alphabet = (alphabet === undefined) ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789": alphabet;
    output = 0;
    stub3_seq = _pyfunc_enumerate(_pymeth_upper.call(val));
    if ((typeof stub3_seq === "object") && (!Array.isArray(stub3_seq))) { stub3_seq = Object.keys(stub3_seq);}
    for (stub4_itr = 0; stub4_itr < stub3_seq.length; stub4_itr += 1) {
        stub5_tgt = stub3_seq[stub4_itr];
        i = stub5_tgt[0]; c = stub5_tgt[1];
        output = _pyfunc_op_add(output, _pyfunc_op_mult(_pymeth_index.call(alphabet, c), Math.pow(36, i)));
    }
    return output & 4294967295;
};

verify_date = function flx_verify_date (date) {
    return (date < 991232) && ((((date / 100) % 100) < 13)) && (((date % 100) < 32));
};

decode_firebeat_recovery_password = function flx_decode_firebeat_recovery_password (inval) {
    var buffer_to_str, checksum, checksum_base, date_num, internal_sum, is_valid, keycode_num, krand, output_buffer, output_str, seed, serial_num, xor_buffer;
    buffer_to_str = (function flx_buffer_to_str (buf) {
        var i, parts, v;
        parts = [];
        for (i = 0; i < 70; i += 10) {
            v = buf.read(i, 10);
            _pymeth_append.call(parts, (Math.floor(v/100) % 10));
            _pymeth_append.call(parts, (Math.floor(v/10) % 10));
            _pymeth_append.call(parts, (v % 10));
        }
        v = buf.read(70, 7);
        _pymeth_append.call(parts, (Math.floor(v/10) % 10));
        _pymeth_append.call(parts, (v % 10));
        return _pymeth_join.call("", ((function list_comprehension (iter0) {var res = [];var c, i0;if ((typeof iter0 === "object") && (!Array.isArray(iter0))) {iter0 = Object.keys(iter0);}for (i0=0; i0<iter0.length; i0++) {c = iter0[i0];{res.push(_pyfunc_str(c));}}return res;}).call(this, parts)));
    }).bind(this);

    inval = _pymeth_replace.call(inval, "-", "");
    krand = new KonamiRand();
    output_buffer = new BitArrayBuffer(112);
    output_buffer.write(0, 31, base36decode(inval.slice(0,6)));
    output_buffer.write(31, 31, base36decode(inval.slice(6,12)));
    output_buffer.write(62, 31, base36decode(inval.slice(12,18)));
    output_buffer.write(93, 10, base36decode(inval.slice(18)));
    seed = output_buffer.read(93, 10);
    checksum_base = output_buffer.read(77, 16);
    krand.seed(_pyfunc_op_mult(seed, 3) + 112);
    checksum = (checksum_base ^ krand.next()) & 65535;
    krand.seed((_pyfunc_op_add(_pyfunc_op_mult(seed, 7), _pyfunc_op_mult(checksum, 5))) + 112);
    xor_buffer = new BitArrayBuffer(108);
    xor_buffer.write(0, 32, krand.next());
    xor_buffer.write(32, 32, krand.next());
    xor_buffer.write(64, 13, krand.next());
    output_buffer.xor(xor_buffer);
    internal_sum = (_pyfunc_sum([output_buffer.read(0, 12), output_buffer.read(12, 12), output_buffer.read(24, 12), output_buffer.read(36, 12), output_buffer.read(48, 12), output_buffer.read(60, 12), output_buffer.read(72, 5)])) & 65535;
    output_str = buffer_to_str(output_buffer);
    serial_num = output_str.slice(0,9);
    keycode_num = output_str.slice(9,17);
    date_num = output_str.slice(17);
    is_valid = _pyfunc_op_equals(checksum, internal_sum) && (serial_num.length == 9) && (keycode_num.length == 8) && (date_num.length == 6) && (_pyfunc_truthy(verify_date(_pyfunc_int(date_num))));
    return ({password: inval, decoded: output_str, serial: serial_num, keycode: keycode_num, date: date_num, is_valid: is_valid});
};

encode_firebeat_recovery_password = function flx_encode_firebeat_recovery_password (serial, keycode, date, seed, verify_password) {
    var checksum, decoded_password, generate_key, internal_sum, k, krand, output_buffer, parts, parts_str, password, str_to_buffer, xor_buffer;
    verify_password = (verify_password === undefined) ? false: verify_password;
    generate_key = (function flx_generate_key (serial, keycode, date) {
        var dnum, nnum, snum;
        if (!(serial.length == 9)) { throw _pyfunc_op_error('AssertionError', "serial.length == 9");}
        if (!(keycode.length == 8)) { throw _pyfunc_op_error('AssertionError', "keycode.length == 8");}
        snum = _pymeth_join.call("", ((function list_comprehension (iter0) {var res = [];var c, i0;if ((typeof iter0 === "object") && (!Array.isArray(iter0))) {iter0 = Object.keys(iter0);}for (i0=0; i0<iter0.length; i0++) {c = iter0[i0];{res.push(_pymeth_format.call("{:c}", (String.fromCharCode(c.charCodeAt(0) - (((c.charCodeAt(0) >= 97))? (49) : (0))))));}}return res;}).call(this, _pymeth_lower.call(serial))));
        nnum = keycode;
        dnum = _pymeth_format.call("{:06d}", ((_pyfunc_truthy(verify_date(date)))? (date) : (0)));
        return _pymeth_join.call("", [snum, nnum, dnum]);
    }).bind(this);

    str_to_buffer = (function flx_str_to_buffer (inval) {
        var i, output_buffer;
        output_buffer = new BitArrayBuffer(112);
        for (i = 0; i < Math.floor(inval.length/3); i += 1) {
            output_buffer.write(_pyfunc_op_mult(i, 10), 10, _pyfunc_int((inval.slice(_pyfunc_op_mult(i, 3),_pyfunc_op_mult(i, 3) + 3))));
        }
        i = Math.floor(inval.length/3);
        output_buffer.write(70, 7, _pyfunc_int((inval.slice(_pyfunc_op_mult(i, 3),_pyfunc_op_mult(i, 3) + 3))));
        return output_buffer;
    }).bind(this);

    k = generate_key(serial, keycode, date);
    output_buffer = str_to_buffer(k);
    internal_sum = (_pyfunc_sum([output_buffer.read(0, 12), output_buffer.read(12, 12), output_buffer.read(24, 12), output_buffer.read(36, 12), output_buffer.read(48, 12), output_buffer.read(60, 12), output_buffer.read(72, 5)])) & 65535;
    krand = new KonamiRand();
    krand.seed(_pyfunc_op_mult(seed, 3) + 112);
    checksum = (internal_sum ^ krand.next()) & 65535;
    output_buffer.write(77, 16, checksum);
    output_buffer.write(93, 10, seed);
    krand.seed((_pyfunc_op_add(_pyfunc_op_mult(seed, 7), _pyfunc_op_mult(internal_sum, 5))) + 112);
    xor_buffer = new BitArrayBuffer(108);
    xor_buffer.write(0, 32, krand.next());
    xor_buffer.write(32, 32, krand.next());
    xor_buffer.write(64, 13, krand.next());
    output_buffer.xor(xor_buffer);
    parts = [base36encode(output_buffer.read(0, 31), 6), base36encode(output_buffer.read(31, 31), 6), base36encode(output_buffer.read(62, 31), 6), base36encode(output_buffer.read(93, 10), 2)];
    parts_str = _pymeth_join.call("", parts);
    password = _pymeth_join.call("-", ((function list_comprehension (iter0) {var res = [];var i, i0;if ((typeof iter0 === "object") && (!Array.isArray(iter0))) {iter0 = Object.keys(iter0);}for (i0=0; i0<iter0.length; i0++) {i = iter0[i0];{res.push(parts_str.slice(i,i + 5));}}return res;}).call(this, _pyfunc_range(0, parts_str.length, 5))));
    if (_pyfunc_truthy(verify_password)) {
        decoded_password = decode_firebeat_recovery_password(password);
        if ((!_pyfunc_truthy(decoded_password["is_valid"]))) {
            return "FAILED";
        }
    }
    return password;
};

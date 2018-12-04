class AbstractLFSR{
  constructor (coefficients_vector) {
    this._coefficients = coefficients_vector;
    this._n = this._coefficients.length;
    this._bit_states = Array(this._n);
    for (var i = 0; i < this._n ; i++) {
      this._bit_states[i] = ["a" + i,];
    }
    return this;
  }

  _xor_bit_states(left, right) {
    let result = left;
    for (let i = 0 ; i < right.length ; i++) {
      let idx = left.indexOf(right[i]);
      if (idx === -1) {
        left.push(right[i]);
      } else {
        left.splice(idx, 1);
      }
    }
    return result;
  }

  next() {
    this._output_bit = this._bit_states.pop();
    this._bit_states.unshift([]); // Zero
    for (let i = 0 ; i < this._n ; i++) {
      if (this._coefficients[i]) {
        this._xor_bit_states(this._bit_states[i], this._output_bit);
      }
    }
    return this._output_bit;
  }
}

<div>

</div>


comCache = [];

function Communicator() {
    comCache.push(this);
    this.CFGHighlight = {
        registers: {},
        statements: {},
        addresses: {},
        highlights: {},
        exits: {},
        blocks: {}
    };
}

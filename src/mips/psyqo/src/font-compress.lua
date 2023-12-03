-- MIT License
--
-- Copyright (c) 2023 PCSX-Redux authors
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.

-- This is the code used to generate the file system-font.inc, from a raw font file.
-- The compression system assumes font width of 8 pixels, but has otherwise no
-- condition on the font height. The expected input file format is to be in raw
-- greyscale 4bpp, fully black and white, meaning each byte from the input file
-- should only have the hexadecimal values 00, 01, 10, or 11. The organization of
-- the input image should be 3 lines of 32 characters, starting with the ascii
-- character 0x20 (space), which has to remain completely blank. This also means
-- we are only representing characters from 0x20 to 0x7f.

-- Note that the compression system uses a lot of optimization tricks around its
-- huffman representation, and it won't necessarily be able to handle any arbitrary
-- input file as a result. Most fonts files should work however, due to their low
-- entropy nature.

-- Run this code with, for example, the following command:
-- ./pcsx-redux -cli -exec "dofile 'font-compress.lua' compressFont 'font.raw' PCSX.quit()"

-- First part of this code is a generic min-heap class. It can easily be extracted
-- into its own independant library for other means.

-- Helpers for the heap's tree navigation
local function getParent(position) return (position - position % 2) / 2 end

local function getLeftChild(position) return position * 2 end

local function getRightChild(position) return position * 2 + 1 end

local function getSibling(position)
    -- basically, xor position with the value 1, without using any bit library.
    return position - (position % 2) * 2 + 1
end

-- Pushes a 'value' into the heap, associated with a weight.
-- The weight can be of any sort of type, as long as it's always possible
-- to do ordered comparisions between all weights of the whole heap.
local function push(heap, value, weight)
    local tree = heap._tree
    -- Puts the new entry at the bottom of the binary tree first.
    local position = #tree + 1
    tree[position] = { value = value, weight = weight }

    -- Then try to bubble the value up, depending on its weight. Lighter means higher.
    local parent = getParent(position)
    while position > 1 and tree[parent].weight > weight do
        tree[position], tree[parent], position, parent = tree[parent], tree[position], parent, getParent(parent)
    end
end

-- Gets the value at the root of the heap, which is the smallest value available.
-- Returns a tuple representing the value, and its weight, respectively.
local function min(heap)
    local tree = heap._tree
    if #tree == 0 then error 'Empty heap' end

    local root = tree[1]
    return root.value, root.weight
end

-- Removes the root of the tree, and returns a tuple representing the value,
-- and its weight, respectively.
local function pop(heap)
    -- Keeps track of our return values.
    local value, weight = min(heap)
    local tree = heap._tree
    local size = #tree
    -- Special case, if we just need to nuke our tree.
    if size == 1 then
        tree[1] = nil
    else
        -- Caching the weight of the value we're going to shove instead
        -- of the root.
        local lastWeight = tree[size].weight
        local position = 1
        -- Basically, we:
        --  (1) nuke the root of tree
        --  (2) move the last element of our tree to the root instead
        tree[position], tree[size], size = tree[size], nil, size - 1
        -- Then we start shuffling down our tree to rebalance it.
        local child = getLeftChild(position)
        if size > child and tree[child].weight > tree[child + 1].weight then child = getSibling(child) end
        while size >= child and tree[child].weight < lastWeight do
            tree[position], tree[child], position, child = tree[child], tree[position], child, getLeftChild(child)
            if size > child and tree[child].weight > tree[child + 1].weight then child = getSibling(child) end
        end
    end
    return value, weight
end

Heap = {
    new = function()
        return { _tree = {}, push = push, pop = pop, min = min, size = function(heap) return #heap._tree end }
    end,
}

-- From there, we have the actual font compression code, which leverages the min-heap code from above.

function compressFont(fontfile)
    -- frequency
    local f = {}
    -- data stream
    local d = {}
    -- input file
    local i = type(fontfile) == 'string' and Support.File.open(fontfile) or fontfile
    -- Read the input file, assumed to be in raw 4bpp greyscale format, fully black and white.
    while not i:eof() do
        local v = 0
        local p = 1
        for b = 1, 4 do
            local c = i:readU8()
            if c == 16 then c = 2 end
            if c == 17 then c = 3 end
            v = v + c * p
            p = p * 4
        end
        d[#d + 1] = v
        if not f[v] then f[v] = 0 end
        f[v] = f[v] + 1
    end

    local h = Heap.new()

    -- feed our frequencies into the min-heap
    for k, w in pairs(f) do h:push({ byte = k }, w) end

    -- then process to build our huffman tree
    while h:size() > 1 do
        local n1, w1 = h:pop()
        local n2, w2 = h:pop()
        h:push({ left = n1, right = n2 }, w1 + w2)
    end
    local tree = h:pop()

    -- augment our tree with our special flat-tree indices, while building
    -- its second part, the lookup table
    local index = 0
    local lut = {}
    local leaves = {}
    local function garnishTree(tree)
        if tree.byte ~= nil then
            local size = #lut
            tree.leaf = size == 0 and 0 or -size
            lut[size + 1] = tree.byte
            leaves[tree.byte] = tree
            tree.byte = nil
            return
        end
        tree.index = index
        index = index + 1
        if tree.left then
            garnishTree(tree.left)
            tree.left.parent = tree
            tree.left.isLeft = true
        end
        if tree.right then
            garnishTree(tree.right)
            tree.right.parent = tree
            tree.right.isRight = true
        end
    end
    garnishTree(tree)
    if index > 62 then error 'File too diverse for compression.' end

    -- and finally build the flat-tree itself
    local btree = {}
    local function buildBinaryTree(tree)
        if tree.left then
            local index = tree.left.index
            if index then
                btree[tree.index * 2 + 1] = index * 2
                buildBinaryTree(tree.left)
            else
                btree[tree.index * 2 + 1] = tree.left.leaf
            end
        end
        if tree.right then
            local index = tree.right.index
            if index then
                btree[tree.index * 2 + 2] = index * 2
                buildBinaryTree(tree.right)
            else
                btree[tree.index * 2 + 2] = tree.right.leaf
            end
        end
    end
    buildBinaryTree(tree)

    -- last step: build the compressed bitstream
    local bitstream = {}
    local bitbucket = 1
    local function pushBit(bit)
        if bitbucket >= 256 then
            bitstream[#bitstream + 1] = bitbucket - 256
            bitbucket = 1
        end
        bitbucket = bitbucket * 2 + bit
    end
    local function encode(byte)
        local function buildEncoding(node)
            if node.parent then buildEncoding(node.parent) end
            pushBit(node.isLeft and 0 or 1)
        end
        buildEncoding(leaves[byte])
    end

    for _, v in ipairs(d) do encode(v) end

    if bitbucket ~= 1 then bitstream[#bitstream + 1] = bitbucket end

    -- all the compression is done, dump everything

    -- pprint(btree)
    -- pprint(lut)
    -- pprint(bitstream)

    local function dumpData(data)
        local len = 0
        local line = '    '
        for _, v in ipairs(data) do
            if len == 13 then
                print(line)
                line = '    '
                len = 0
            end
            if v < 0 then v = 256 + v end
            line = line .. string.format('0x%02x, ', v)
            len = len + 1
        end
        print(line)
    end

    print 'static const unsigned char s_compressedTexture[] = {'
    print '    // offsets to luts and bitstream'
    print(string.format('    0x%02x, 0x%02x,', #btree + 2, #btree + #lut + 2))
    print ''

    print '    // binary tree'
    dumpData(btree)
    print ''

    print '    // lut'
    dumpData(lut)
    print ''

    print '    // bitstream'
    dumpData(bitstream)
    print '};'
end

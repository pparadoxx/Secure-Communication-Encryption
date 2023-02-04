-- Secure Copy
local G = table.Copy(_G)

-- Global Table
sce = {}

-- Generate Key
function sce.Key(length)
    if !length then length = 64 end 

    local str = ""

    for i = 1, length do 
        str = str .. G.string.char(G.math.random(97,122))
    end

    return str 
end

-- Table Hash
function sce.HashTable(tab)
    if !tab || !G.istable(tab) then return end 

    local str = ""

    for k,v in G.pairs(tab) do
        local gi = G.debug.getinfo( v )

        str = str .. G.util.MD5(G.util.TypeToString(gi.linedefined .. " " .. gi.short_src))
    end 

    return G.util.SHA256(str)
end

-- Error Handler
function sce.HandleErrors(errtype,ply)
    // Update
    return
end

-- Hash Key
function sce.Hash(str) // Returns a 1024 long hashed key
    local sha = G.util.SHA256(str) // Largest one carried by default in GLua
    return G.string.rep(sha, 16)
end

-- To ASCII
function sce.ToASCII(table)
    for k,v in G.ipairs(table) do 
        if !isstring(v) then return end 

        table[k] = G.string.byte(v)
    end

    return table 
end

-- Encryption
function sce.Encrypt(str,key)
    str = sce.ToASCII(str:ToTable()) // Convert to a table and then convert those strings in the table into numbers (ie: a = 97)
    key = sce.ToASCII(sce.Hash(key):ToTable()) 

    // MATH //
    for k,v in G.ipairs(str) do
        local kv = key[k] 

        str[k] = (v+kv)
    end

    // SHIFT ROWS & SWAP //
    for k,v in G.ipairs(str) do 
        local kv = key[k] 

        str[k] = G.bit.bswap(G.bit.rol(v, kv)) // DEVNOTE: Reverse: bit.ror(bit.bswap(v), kv)
    end

    // XOR // 
    for k,v in G.ipairs(str) do 
        local kv = key[k] 

        str[k] = G.bit.bxor(v, kv)
    end


    return G.util.Base64Encode(G.table.concat(str, " "))
end

-- Decryption
function sce.Decrypt(str,key)
    str = G.string.Split(G.util.Base64Decode(str), " ")
    key = sce.ToASCII(sce.Hash(key):ToTable()) 

    // XOR // 
    for k,v in G.ipairs(str) do 
        local kv = key[k] 

        str[k] = G.bit.bxor(v, kv)
    end

    // SHIFT ROWS & SWAP //
    for k,v in G.ipairs(str) do 
        local kv = key[k] 

        str[k] = G.bit.ror(G.bit.bswap(v), kv)
    end

    // MATH //
    for k,v in G.ipairs(str) do
        local kv = key[k] 

        str[k] = (v-kv)
    end

    // REBUILD //
    for k,v in G.ipairs(str) do 
        local success, code = G.pcall(G.string.char, v)
        
        if success then 
            str[k] = code 
        else
            return sce.HandleErrors("Invalid Return Data")
        end
    end

    return G.table.concat(str)
end

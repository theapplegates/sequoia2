-- Tweaks our manual pages during conversion to html by pandoc.
--
-- See https://pandoc.org/lua-filters.html#debugging-lua-filters on
-- how to debug and develop these filters.

-- Overwrites the title.
--
-- It just says 'sq` which looks odd.
function Meta(m)
   m.title = "Sequoia PGP Manual Pages"
   return m
end

-- Turns subcommand headers into links.
function Header (h)
   -- Given a sequence of subcommands, return the appropriate file
   -- name.
   local function subcommand_to_link (s)
      t = ""
      for i = 1, #s do
         if s[i].t == 'Space' then
            t = t .. '-'
         else
            t = t ..  s[i].text
         end
      end
      return t .. ".1.html"
   end

   if h.c[1].t == 'Str' and h.c[1].text == 'sq' then
      h.c = pandoc.Link(h.c, subcommand_to_link(h.c))
      return h
   end
end

-- Transform the entries in the "SYNOPSIS" section into links.
local function rewrite_synopsis (inlines)
   -- Returns true if we're looking at a synopsis entry.
   --
   -- Matches on the following sequence:
   --
   --      [1] LineBreak {}
   --      [2] Strong {
   --        content: Inlines[7] {
   --          [1] Str "sq"
   --          [2] Space
   --          [3] Str "key"
   --          [4] Space
   --          [5] Str "userid"
   --          [6] Space
   --          [7] Str "add"
   --        }
   --      }
   --      [3] Space
   --      [4] Str "["
   local function synopsis_p (s)
      return s[1] and s[1].t == 'LineBreak'
         and s[2] and s[2].t == 'Strong'
         and s[2].c[1].text == 'sq' and s[2].c[2].t == 'Space'
         and s[3] and s[3].t == 'Space'
         and s[4] and s[4].t == 'Str' and s[4].text == '['
   end

   -- Given a sequence of subcommands, return the appropriate file
   -- name.
   local function subcommand_to_link (s)
      t = ""
      for i = 1, #s do
         if s[i].t == 'Space' then
            t = t .. '-'
         else
            t = t ..  s[i].text
         end
      end
      return t .. ".1.html"
   end

   for i = 1, #inlines-4 do
      if synopsis_p(table.pack(table.unpack(inlines, i, i + 3))) then
         inlines[i+1] = pandoc.Link(inlines[i+1], subcommand_to_link(inlines[i+1].c))
      end
   end
end

-- Transforms the entries in the "SEE ALSO" section into links.
local function rewrite_see_also (inlines)
   -- Returns true if we're looking at a see-also entry.
   --
   -- Matches on the following sequence:
   --
   --      [43] Strong {
   --        content: Inlines[1] {
   --          [1] Str "sq-wkd"
   --        }
   --      }
   --      [44] Str "(1),"
   local function see_also_p (a, b)
      return a and a.t == 'Strong'
         and b and b.t == 'Str' and string.sub(b.text, 1, 3) == '(1)'
   end

   for i = 1, #inlines-1 do
      if see_also_p(inlines[i], inlines[i+1]) then
         inlines[i] = pandoc.Link(inlines[i], inlines[i].c[1].text .. ".1.html")
      end
   end
end

-- Transforms text enclosed in backticks into inline code or links.
local function rewrite_inline_code (inlines)
   -- Returns the length of the token stream containing quoted text
   -- starting from the first token, or nil if no quoted text is
   -- found.
   local function inline_quoted (s)
      if s[1] and s[1].t == 'Str' and string.sub(s[1].text, 1, 1) == "`" then
         -- Find the end, i.e. the first token containing the closing
         -- tick (which may be the first token).
         for i = 1, #s do
            if s[i] and s[i].t == 'Str' and string.find(s[i].text, "`", 2) then
               return i
            end
         end
      end
   end

   -- Given a sequence of tokens, returns the text representation.
   local function tokens_to_text (s)
      t = ""
      for i = 1, #s do
         if s[i].t == 'Space' then
            t = t .. ' '
         else
            t = t ..  s[i].text
         end
      end
      return t
   end

   -- Given a string subcommand, return the appropriate file
   -- name.
   local function subcommand_to_link (s)
      return string.gsub(s, " ", "-") .. ".1.html"
   end

   for i = 1, #inlines do
      local len = inline_quoted(table.pack(table.unpack(inlines, i)))
      if len then
         -- First, flatten the matched tokens to a text.
         local text = tokens_to_text(table.pack(table.unpack(inlines, i, i+len)))

         -- Then, remove the tokens from the AST.
         for j = math.min(i+len, #inlines), i, -1 do
            inlines:remove(j)
         end

         -- We need to create a replacement node.
         local replacement

         -- See if the quoted text is a reference to a (sub)command.
         local s, e = string.find(text, "`sq[^`]*`")
         if s then
            -- If so, we turn it into a link.
            local sub = string.sub(text, s+1, e-1)
            replacement = pandoc.Link(sub, subcommand_to_link(sub))
         else
            s, e = string.find(text, "`[^`]*`")
            replacement = pandoc.Code(string.sub(text, s+1, e-1))
         end

         -- Finally, insert prefix, replacement, and suffix into the
         -- AST.
         inlines:insert(i+0, pandoc.Str(string.sub(text, 1, s-1)))
         inlines:insert(i+1, replacement)
         inlines:insert(i+2, pandoc.Str(string.sub(text, e+1)))
      end
   end
end

function Inlines (inlines)
   rewrite_synopsis(inlines)
   rewrite_see_also(inlines)
   rewrite_inline_code(inlines)
   return inlines
end

-- Turns implicit links into actual links.
function Str (s)
   s = s.text
   a, b = string.find(s, "<https://[^>]+>")
   if a and b then
      target = string.sub(s, a+1, b-1)
      return pandoc.Inlines {
         pandoc.Str(string.sub(s, 0, a)),
         pandoc.Link(target, target),
         pandoc.Str(string.sub(s, b)),
      }
   end
end

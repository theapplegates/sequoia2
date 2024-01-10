-- Tweaks our manual pages during conversion to html by pandoc.
--
-- See https://pandoc.org/lua-filters.html#debugging-lua-filters on
-- how to debug and develop these filters.

-- Overwrites the title.
--
-- It just says 'sq` which looks odd.
function Meta(m)
   m.title = "Sequoia-PGP Manual Pages"
   return m
end

-- Transform the entries in the "SYNOPSIS" section into links.
local function rewrite_synopsis (inlines)
   -- Returns true if we're looking at a synopsis entry.
   --
   -- Matches on the following sequence:
   --
   --      [1] LineBreak {}
   --      [2] Strong {
   --        content: Inlines[1] {
   --          [1] Str "sq"
   --        }
   --      }
   --      [3] Space
   --      [4] Str "["
   --      [5] Emph {
   --        content: Inlines[3] {
   --          [1] Str "GLOBAL"
   --          [2] Space
   --          [3] Str "OPTIONS"
   --        }
   --      }
   --      [6] Str "]"
   --      [7] Space
   --      [8] Strong {
   --        content: Inlines[5] {
   --          [1] Str "key"
   --          [2] Space
   --          [3] Str "userid"
   --          [4] Space
   --          [5] Str "add"
   --        }
   --      }
   --      [9] Space
   local function synopsis_p (s)
      return s[1] and s[1].t == 'LineBreak'
         and s[2] and s[2].t == 'Strong' and s[2].c[1].text == 'sq'
         and s[3] and s[3].t == 'Space'
         and s[4] and s[4].t == 'Str' and s[4].text == '['
         and s[6] and s[6].t == 'Str' and s[6].text == ']'
         and s[7] and s[7].t == 'Space'
         and s[8] and s[8].t == 'Strong'
         and s[9] and s[9].t == 'Space'
   end

   -- Given a sequence of subcommands, return the appropriate file
   -- name.
   local function subcommand_to_link (s)
      t = "sq-"
      for i = 1, #s do
         if s[i].t == 'Space' then
            t = t .. '-'
         else
            t = t ..  s[i].text
         end
      end
      return t .. ".1.html"
   end

   for i = 1, #inlines-9 do
      if synopsis_p(table.pack(table.unpack(inlines, i, i + 8))) then
         inlines[i+7] = pandoc.Link(inlines[i+7], subcommand_to_link(inlines[i+7].c))
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

function Inlines (inlines)
   rewrite_synopsis(inlines)
   rewrite_see_also(inlines)
   return inlines
end

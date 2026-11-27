# Brightsurf block lists

The ad and tracker block lists used by [Brightsurf](https://brightmadestudios.com), a browser for iPhone by Brightmade Studios LLC.

These are [EasyList and EasyPrivacy](https://easylist.to), converted to WebKit's content blocking format by `tools/convert.py`. A GitHub workflow refreshes them every Monday, and Brightsurf downloads them once a week. The app sends nothing about you or your browsing; it's a plain download of these public files.

| File | What it is |
| --- | --- |
| `lists/blocklists.json` | List of files, rule counts and versions. The app reads this first |
| `lists/ads-*.json` | EasyList, split so one bad file can't stop the rest |
| `lists/trackers-*.json` | EasyPrivacy, split the same way |

## License

EasyList and EasyPrivacy are by The EasyList authors and licensed under [Creative Commons Attribution-ShareAlike 3.0](https://creativecommons.org/licenses/by-sa/3.0/). The converted lists in `lists/` are shared under the same license. The converter script is by Brightmade Studios LLC.

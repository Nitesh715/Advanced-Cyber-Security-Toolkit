
print("="*50)
print("Advanced Cyber Security Toolkit")
print("="*50)

print("1. Port Scanner")
print("2. Network Scanner")
print("3. DNS Lookup")
print("4. Exit")
print("5. About")

choice = input("choose Option : ")

if choice=="1":
      print("Opening Port Scanner... ")

elif choice=="2":
      print("Opening Network Scanner...")

elif choice=="3":
      print("Opening DNS Lookup...")
    
elif choice=="4":
      print("Thank You")

elif choice=="5":
      print("Advanced Cyber Security Toolkit \n Version : 1.0  \n Developer : Nitesh")

else:
      print("Invalid Choice") 

import scanner

if choice=="1":
      scanner.start()

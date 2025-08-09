///////Hello World
/*function greet(name: string): string {
    return `Hello, ${name}!`;
  }
  
  console.log(greet("world"));
  */
 ////////////////


 ////////Hello world 2
/*
export function add(a: number, b: number): number {
  return a + b;
}

// Learn more at https://docs.deno.com/runtime/manual/examples/module_metadata#concepts
if (import.meta.main) {
  console.log("Add 2 + 3 =", add(2, 3));
}
*/
///////////////////////

import { DB } from "https://deno.land/x/sqlite/mod.ts";

const db = new DB("test.db");

db.close();

console.log("Success baby.");
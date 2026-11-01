/**
 * The one test double of the person's card (D283). `?data=demo|worst|empty|one` picks the toggle's data set at load.
 * Mockup only.
 */
import { createAccountDouble, DATA_IDS, type AccountDouble, type DataId } from "./double";

let shared: AccountDouble | undefined;

export function dataFromUrl(): DataId {
  const id = new URLSearchParams(location.search).get("data");
  return (DATA_IDS as string[]).includes(id ?? "") ? (id as DataId) : "demo";
}

export function accountDouble(): AccountDouble {
  if (shared) return shared;
  shared = createAccountDouble("community");
  const data = dataFromUrl();
  if (data !== "demo") shared.setData(data);
  return shared;
}
